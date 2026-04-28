"""Memcached unauthenticated access detection — also flags UDP amplification risk (CVE-2018-1000115)."""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class MemcachedUnauthPlugin(PluginBase):
    id = "services.memcached_unauth"
    name = "Memcached Unauthenticated Access"
    description = (
        "Detect Memcached instances that accept connections without authentication, "
        "exposing cached data and enabling UDP amplification attacks"
    )
    category = PluginCategory.services
    severity = Severity.high
    ports = [11211]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number != 11211 or port.state != "open":
                continue
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, self._probe_sync, host.ip, port.number)
            if result is not None:
                findings.append(result)
        return findings

    def _probe_sync(self, ip: str, port: int) -> FindingData | None:
        try:
            import socket

            sock = socket.create_connection((ip, port), timeout=5)
            sock.sendall(b"stats\r\n")

            # Read until we see END\r\n or a reasonable buffer is filled
            data = b""
            sock.settimeout(3.0)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"END\r\n" in data or b"ERROR" in data:
                        break
                    if len(data) > 65536:  # safety cap
                        break
            except socket.timeout:
                pass
            finally:
                sock.close()

            decoded = data.decode(errors="ignore")
            if "STAT " not in decoded:
                return None

            stats = self._parse_stats(decoded)
            version = stats.get("version", "?")
            curr_items = stats.get("curr_items", "?")
            try:
                mem_mb = int(stats.get("bytes", "0")) // 1024 // 1024
                mem_str = f"{mem_mb}MB"
            except (ValueError, TypeError):
                mem_str = "?"

            return FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title="Memcached Unauthenticated Access",
                description=(
                    "The Memcached instance on port 11211 accepts unauthenticated connections "
                    "and responded to a stats command. An attacker can read or delete all cached "
                    "data (which may include session tokens, API keys, or PII), write arbitrary "
                    "cache entries to poison application data, and enumerate internal service "
                    "behaviour via statistics. "
                    "Additionally, if UDP is enabled, Memcached can be abused for amplification "
                    "DDoS attacks (CVE-2018-1000115): a 15-byte UDP request can generate a "
                    "response of up to 1 MB, providing an amplification factor of ~50,000x."
                ),
                evidence=(
                    f"version: {version}, items: {curr_items}, memory: {mem_str} — "
                    "server responded to unauthenticated stats command"
                ),
                remediation=(
                    "Bind Memcached to localhost or an internal interface only "
                    "(use -l 127.0.0.1 in the startup arguments). "
                    "Enable SASL authentication if the Memcached version supports it. "
                    "Block TCP and UDP port 11211 at the perimeter firewall. "
                    "If UDP is not required, disable it with the -U 0 flag. "
                    "Place Memcached behind an application layer that handles auth."
                ),
                references=[
                    "https://github.com/memcached/memcached/wiki/SecurityRecommendations",
                    "https://nvd.nist.gov/vuln/detail/CVE-2018-1000115",
                ],
                port_number=port,
                protocol="tcp",
            )

        except Exception:
            logger.debug("memcached_unauth: probe failed for %s:%d", ip, port, exc_info=True)
            return None

    def _parse_stats(self, data: str) -> dict[str, str]:
        """Parse Memcached stats response into a key→value dictionary."""
        stats: dict[str, str] = {}
        for line in data.splitlines():
            if line.startswith("STAT "):
                parts = line.split()
                if len(parts) == 3:
                    stats[parts[1]] = parts[2]
        return stats
