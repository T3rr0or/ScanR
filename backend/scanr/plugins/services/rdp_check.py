"""RDP security check.

Checks:
1. NLA (Network Level Authentication) enforcement
2. BlueKeep (CVE-2019-0708) indicator via version negotiation
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# RDP negotiation request (TPKT + X.224 Connection Request)
RDP_NEG_REQ = bytes.fromhex(
    "030000130ee00000000000001d0000000000"
)


class RdpCheckPlugin(PluginBase):
    id = "services.rdp_check"
    name = "RDP Security Check"
    description = "Check RDP for NLA enforcement and BlueKeep vulnerability indicators"
    category = PluginCategory.services
    severity = Severity.high
    cve_ids = ["CVE-2019-0708"]
    ports = [3389]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number != 3389 or port.state != "open":
                continue

            nla_required = await self._check_nla(host.ip, port.number)
            if nla_required is False:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="RDP: Network Level Authentication (NLA) Not Required",
                    description=(
                        "RDP is accessible without NLA (Network Level Authentication). "
                        "This exposes the Windows login screen before authentication and "
                        "increases the attack surface for credential-based attacks."
                    ),
                    evidence=f"RDP on {host.ip}:3389 does not require NLA (security protocol: Classic RDP)",
                    remediation=(
                        "Enable NLA via GPO: Computer Configuration → Administrative Templates → "
                        "Windows Components → Remote Desktop Services → "
                        "Require NLA for remote connections."
                    ),
                    cve_ids=["CVE-2019-0708"],
                    port_number=3389,
                    protocol="tcp",
                ))
        return findings

    async def _check_nla(self, ip: str, port: int) -> bool | None:
        """Return True if NLA required, False if not, None on error."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5
            )
            writer.write(RDP_NEG_REQ)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=4)
            writer.close()
            # Parse negotiation response
            # Byte 11 = type (02 = RDP_NEG_RSP), bytes 12-15 = flags + protocol
            if len(resp) >= 19 and resp[11] == 0x02:
                selected_protocol = int.from_bytes(resp[15:19], "little")
                # protocol 0 = Classic RDP (no NLA), 1 = TLS, 2 = CredSSP/NLA
                return selected_protocol >= 2
            return None
        except Exception:
            return None
