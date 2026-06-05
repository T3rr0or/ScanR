from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class RedisUnauthPlugin(PluginBase):
    id = "services.redis_unauth"
    name = "Redis Unauthenticated Access"
    description = "Detect Redis instances with no authentication required"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [6379, 6380]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in (6379, 6380) or port.state != "open":
                continue
            result = await self._probe(host.ip, port.number)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, ip: str, port: int) -> FindingData | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5.0
            )
            writer.write(b"PING\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(64), timeout=3.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if data and (data.startswith(b"+PONG") or b"PONG" in data):
                # Try INFO to get version
                try:
                    reader2, writer2 = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=5.0
                    )
                    writer2.write(b"INFO server\r\n")
                    await writer2.drain()
                    info = await asyncio.wait_for(reader2.read(512), timeout=3.0)
                    writer2.close()
                    version_line = next((line for line in info.decode(errors="ignore").splitlines() if "redis_version" in line), "")
                    version = version_line.split(":")[1].strip() if ":" in version_line else "unknown"
                except Exception:
                    version = "unknown"

                return FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="Redis Unauthenticated Access",
                    description=(
                        f"The Redis instance on port {port} accepts connections without authentication. "
                        "An attacker can read/write all cached data, execute Lua scripts, "
                        "and potentially achieve remote code execution via config manipulation."
                    ),
                    evidence=f"PING → PONG (no auth required, Redis {version})",
                    remediation=(
                        "Enable Redis authentication with a strong password (requirepass). "
                        "Bind Redis to localhost or internal IPs only. "
                        "Use firewall rules to restrict port 6379 access."
                    ),
                    references=[
                        "https://redis.io/docs/management/security/",
                        "https://redis.io/docs/management/security/acl/",
                    ],
                    port_number=port,
                    protocol="tcp",
                )
        except Exception:
            pass
        return None
