"""NetBIOS information enumeration plugin.

Sends a NetBIOS Name Service (NBNS) status request to UDP 137
and parses the response to enumerate registered names, workgroup, and MAC address.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# NetBIOS node status request
_NBNS_STATUS = bytes([
    0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
    0x00, 0x01,
])

_NAME_TYPES = {
    0x00: "Workstation",
    0x03: "Messenger",
    0x06: "RAS Server",
    0x1B: "Domain Master Browser",
    0x1C: "Domain Controllers",
    0x1D: "Master Browser",
    0x1E: "Browser Election",
    0x20: "File Server",
}


class NetbiosInfoPlugin(PluginBase):
    id = "services.netbios_info"
    name = "NetBIOS Information"
    description = "Enumerate NetBIOS names, workgroup, and MAC via UDP 137"
    category = PluginCategory.network
    severity = Severity.info
    ports = [137]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._query_netbios, host.ip)
        if not result:
            return []
        names, mac = result
        if not names:
            return []

        workgroup = next((n for n, t in names if t in (0x00, 0x1B, 0x1C, 0x1D, 0x1E)), None)
        hostname = next((n for n, t in names if t == 0x00), None)
        detail_lines = [f"{n} <{t:02X}> ({_NAME_TYPES.get(t, 'Unknown')})" for n, t in names]

        return [FindingData(
            plugin_id=self.id,
            severity=Severity.info,
            title="NetBIOS Names Disclosed",
            description=(
                "The host responded to a NetBIOS Name Service status query. "
                "NetBIOS name information can reveal hostname, workgroup/domain membership, "
                "and MAC address — useful for network mapping but also for attackers."
            ),
            evidence=(
                f"Hostname: {hostname or 'N/A'}\n"
                f"Workgroup/Domain: {workgroup or 'N/A'}\n"
                f"MAC: {mac or 'N/A'}\n"
                "Names:\n  " + "\n  ".join(detail_lines)
            ),
            remediation="Consider blocking UDP 137 at the network perimeter to prevent external enumeration.",
            port_number=137,
            protocol="udp",
        )]

    def _query_netbios(self, ip: str) -> tuple[list[tuple[str, int]], str | None] | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(_NBNS_STATUS, (ip, 137))
            data, _ = sock.recvfrom(1024)
            sock.close()
            return _parse_nbns_response(data)
        except Exception:
            return None


def _parse_nbns_response(data: bytes) -> tuple[list[tuple[str, int]], str | None] | None:
    if len(data) < 57:
        return None
    name_count = data[56]
    offset = 57
    names: list[tuple[str, int]] = []
    for _ in range(name_count):
        if offset + 18 > len(data):
            break
        raw_name = data[offset:offset + 15].decode("ascii", errors="replace").rstrip()
        name_type = data[offset + 15]
        names.append((raw_name, name_type))
        offset += 18

    # MAC address follows the names table
    mac: str | None = None
    if offset + 6 <= len(data):
        mac = ":".join(f"{b:02X}" for b in data[offset:offset + 6])

    return names, mac
