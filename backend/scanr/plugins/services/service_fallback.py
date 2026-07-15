"""Detect common services on non-standard ports (definitive-signal fallback).

Most service plugins are locked to fixed ports (FTP 21, SMTP 25, VNC 5900, Redis
6379, …), so the service is invisible when it runs on an unusual port. This
plugin probes every open, otherwise-unidentified TCP port and confirms a service
only on an unambiguous signal — never a guess:

- VNC   : the ``RFB 00x.00y`` protocol magic (unique).
- SMTP  : an ``ESMTP`` / ``220 … smtp`` greeting.
- FTP   : a ``220`` greeting naming a known FTP daemon or containing "ftp".
- Redis : an active ``PING`` that returns ``+PONG`` (unauthenticated) or a
          ``-NOAUTH`` error (auth-protected).

A bare ``220`` with no FTP/SMTP marker is left unclassified — no false positives.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.scanner.fingerprint.banner_grabber import grab_banner

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# Ports already handled by the dedicated service/SSH/telnet plugins.
_COVERED_PORTS = {
    21, 22, 23, 25, 139, 161, 389, 445, 465, 587, 636, 993, 995, 1433, 2022,
    2222, 2323, 2525, 3268, 3269, 3306, 3389, 5432, 5900, 5901, 5902, 5903,
    5985, 5986, 6379, 6380, 9200, 11211, 22222, 27017, 27018, 27019,
}
_MAX_CANDIDATES = 150
_MAX_REDIS_PROBES = 60
_CONCURRENCY = 20

# Services whose banner names should still be probed (nmap sometimes gets these
# wrong on odd ports); anything else nmap positively identified is left alone.
_TARGET_HINTS = ("ftp", "smtp", "vnc", "redis")


def _classify_banner(banner: str | None) -> str | None:
    """Return 'vnc' | 'smtp' | 'ftp' from a definitive banner signature, else None."""
    if not banner:
        return None
    b = banner.strip()
    low = b.lower()
    if b.startswith("RFB 00"):
        return "vnc"
    if "esmtp" in low or (b.startswith("220") and "smtp" in low):
        return "smtp"
    if any(d in low for d in ("vsftpd", "proftpd", "filezilla", "pure-ftpd", "microsoft ftp")) or (
        b.startswith("220") and "ftp" in low
    ):
        return "ftp"
    return None


class ServiceFallbackPlugin(PluginBase):
    id = "services.service_fallback"
    name = "Service on Non-Standard Port"
    description = "Detect FTP/SMTP/VNC/Redis running on non-standard ports via a definitive signal"
    category = PluginCategory.services
    severity = Severity.low
    ports = None  # all ports

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        candidates: list[int] = []
        for p in host.ports:
            if p.state != "open" or p.number in _COVERED_PORTS:
                continue
            svc = (p.service.name.lower() if p.service and p.service.name else "")
            # Probe ports nmap left unidentified, or that already look like a target.
            if svc and not any(h in svc for h in _TARGET_HINTS):
                continue
            candidates.append(p.number)
            if len(candidates) >= _MAX_CANDIDATES:
                break
        if not candidates:
            return []

        sem = asyncio.Semaphore(_CONCURRENCY)
        redis_budget = [_MAX_REDIS_PROBES]

        async def probe(port: int) -> list[FindingData]:
            async with sem:
                try:
                    banner = await grab_banner(host.ip, port)
                except Exception:  # noqa: BLE001
                    banner = None
                kind = _classify_banner(banner)
                if kind:
                    return self._banner_findings(kind, host.ip, port, (banner or "").strip())
                # No banner signature — try one cheap Redis handshake (bounded).
                if banner is None and redis_budget[0] > 0:
                    redis_budget[0] -= 1
                    state = await self._probe_redis(host.ip, port)
                    if state:
                        return self._redis_findings(state, host.ip, port)
                return []

        results = await asyncio.gather(*[probe(p) for p in candidates])
        return [f for group in results for f in group]

    def _banner_findings(self, kind: str, ip: str, port: int, banner: str) -> list[FindingData]:
        meta = {
            "vnc": (Severity.low, "VNC Service on Non-Standard Port",
                    "A VNC remote-desktop service is exposed here. VNC often has weak or legacy "
                    "authentication and should not be internet-facing.",
                    "Restrict VNC to trusted networks/VPN and require strong authentication."),
            "smtp": (Severity.info, "SMTP Service on Non-Standard Port",
                     "An SMTP mail service is exposed on a non-standard port.",
                     "Confirm this mail service is intended and not an open relay; restrict access."),
            "ftp": (Severity.low, "FTP Service on Non-Standard Port",
                    "An FTP service is exposed here. FTP transmits credentials and data in cleartext.",
                    "Replace FTP with SFTP/FTPS and restrict access."),
        }
        sev, title, desc, remediation = meta[kind]
        return [FindingData(
            plugin_id=self.id, severity=sev, title=f"{title} ({port})",
            description=desc,
            evidence=f"{ip}:{port} banner: {banner[:200]}" if banner else f"{ip}:{port}",
            remediation=remediation,
            references=["https://cwe.mitre.org/data/definitions/1327.html"],
            port_number=port, protocol="tcp",
        )]

    async def _probe_redis(self, ip: str, port: int) -> str | None:
        """Return 'unauth' (PING→PONG), 'auth' (-NOAUTH), or None (not Redis)."""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=4.0)
        except Exception:  # noqa: BLE001
            return None
        try:
            writer.write(b"*1\r\n$4\r\nPING\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(64), timeout=3.0)
        except Exception:  # noqa: BLE001
            data = b""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        if not data:
            return None
        if data.startswith(b"+PONG") or b"PONG" in data:
            return "unauth"
        if b"NOAUTH" in data:
            return "auth"
        return None

    def _redis_findings(self, state: str, ip: str, port: int) -> list[FindingData]:
        if state == "unauth":
            return [FindingData(
                plugin_id=self.id, severity=Severity.high,
                title=f"Unauthenticated Redis on Non-Standard Port ({port})",
                description=(
                    "A Redis server on a non-standard port accepts commands without authentication. "
                    "An attacker can read/write all data and often achieve remote code execution "
                    "(e.g. via CONFIG SET + module load or writing an SSH key/cron job)."
                ),
                evidence=f"{ip}:{port} replied +PONG to an unauthenticated PING",
                remediation="Require a password (requirepass) / ACLs, bind to localhost, and firewall the port.",
                references=["https://redis.io/docs/management/security/"],
                port_number=port, protocol="tcp",
            )]
        return [FindingData(
            plugin_id=self.id, severity=Severity.low,
            title=f"Redis Service on Non-Standard Port ({port})",
            description="A password-protected Redis server is exposed on a non-standard port.",
            evidence=f"{ip}:{port} replied -NOAUTH to PING",
            remediation="Confirm the exposure is intended; restrict Redis to trusted networks.",
            port_number=port, protocol="tcp",
        )]
