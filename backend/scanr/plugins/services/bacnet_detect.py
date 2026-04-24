from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class BacnetDetectPlugin(PluginBase):
    id = "services.bacnet_detect"
    name = "BACnet Building Automation System Detection"
    description = "Detect exposed BACnet building automation system protocol"
    category = PluginCategory.services
    severity = Severity.high
    ports = [47808]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        # BACnet is UDP — may not appear in standard TCP port scans.
        # Run probe if any ports found on this host (it's reachable)
        # OR if 47808 appears in discovered ports.
        has_bacnet_port = any(p.number == 47808 for p in host.ports)
        has_any_port = bool(host.ports)

        if not has_bacnet_port and not has_any_port:
            return []

        result = await asyncio.get_event_loop().run_in_executor(
            None, self._probe_bacnet, host.ip, 47808
        )
        if result:
            return [self._make_finding(host.ip, result)]
        return []

    def _probe_bacnet(self, ip: str, port: int) -> dict | None:
        import socket
        import struct

        # BACnet Who-Is packet (no range = request all devices)
        # BVLC: type=0x81 (BACnet/IP), func=0x0a (Original-Unicast-NPDU), length=0x0008
        # NPDU: version=0x01, control=0x00
        # APDU: PDU type = Unconfirmed-Req (0x10), service = Who-Is (0x08)
        who_is = bytes([
            0x81, 0x0a, 0x00, 0x08,  # BVLC header (length=8)
            0x01, 0x00,               # NPDU
            0x10, 0x08,               # APDU: Unconfirmed-Req, Who-Is
        ])

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(who_is, (ip, port))

            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                sock.close()
                return None
            sock.close()

            if not data or len(data) < 4:
                return None

            # Verify BVLC type = 0x81 (BACnet/IP)
            if data[0] != 0x81:
                return None

            result = {"device_name": None, "vendor": None, "instance": None}

            # Parse I-Am response (APDU service = 0x00 = I-Am, Unconfirmed-Req)
            # APDU starts at offset 6 (after BVLC 4 + NPDU 2)
            if len(data) >= 8:
                apdu_type = data[6] & 0xF0  # Upper nibble
                service = data[7] if len(data) > 7 else 0

                if apdu_type == 0x10 and service == 0x00:  # Unconfirmed-Req, I-Am
                    result["vendor"] = "BACnet Device"
                    if len(data) > 11:
                        try:
                            obj_id_raw = struct.unpack_from(">I", data, 10)[0]
                            instance = obj_id_raw & 0x3FFFFF
                            result["instance"] = instance
                        except Exception:
                            pass

            return result
        except Exception:
            return None

    def _make_finding(self, ip: str, result: dict) -> FindingData:
        instance = result.get("instance")
        instance_str = str(instance) if instance is not None else "unknown"
        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="BACnet Building Automation System Exposed",
            description=(
                "BACnet is a building automation protocol used for HVAC, lighting, access control, "
                "and fire systems. Unauthenticated access can reveal building layout and potentially "
                "allow manipulation of building systems."
            ),
            evidence=f"BACnet I-Am response received. Device instance: {instance_str}",
            remediation=(
                "Segment BACnet networks from IT networks and the internet. "
                "Use BACnet/SC (Secure Connect) for encrypted communications. "
                "Implement network-level access controls on UDP 47808."
            ),
            references=[
                "https://www.cisa.gov/sites/default/files/publications/Managing_Cybersecurity_in_Building_Systems_S508C.pdf",
            ],
            port_number=47808,
            protocol="udp",
        )
