from __future__ import annotations

import asyncio
import logging
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class VncAuthPlugin(PluginBase):
    id = "services.vnc_auth"
    name = "VNC Authentication Check"
    description = "Check for VNC no-authentication security type"
    category = PluginCategory.services
    severity = Severity.high
    ports = [5900, 5901, 5902, 5903]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in self.ports or port.state != "open":
                continue
            no_auth = await self._check_vnc_auth(host.ip, port.number)
            if no_auth:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="VNC No-Authentication Security Type",
                    description=(
                        "VNC server offers security type 1 (None), allowing unauthenticated access. "
                        "Anyone can connect and control the desktop."
                    ),
                    evidence=f"VNC on {host.ip}:{port.number} offered security type: None (1)",
                    remediation="Enable VNC authentication. Use VNC password or require SSH tunneling for VNC connections.",
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _check_vnc_auth(self, ip: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5
            )
            # Read server version
            version = await asyncio.wait_for(reader.read(12), timeout=3)
            if not version.startswith(b"RFB "):
                writer.close()
                return False
            # Send client version
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            # Read security types
            data = await asyncio.wait_for(reader.read(2), timeout=3)
            if len(data) < 2:
                writer.close()
                return False
            num_types = data[0]
            types_data = await asyncio.wait_for(reader.read(num_types), timeout=3)
            writer.close()
            # Security type 1 = None (no auth)
            return 1 in types_data
        except Exception:
            return False
