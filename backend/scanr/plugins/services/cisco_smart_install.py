"""Cisco Smart Install vulnerability check.

Cisco Smart Install (port 4786/tcp) is a zero-touch deployment protocol.
When exposed, attackers can abuse it to retrieve startup configurations,
replace configuration files, or upgrade firmware without authentication.
This has been actively exploited in the wild (CVE-2018-0171).
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class CiscoSmartInstallPlugin(PluginBase):
    id = "services.cisco_smart_install"
    name = "Cisco Smart Install Exposed"
    description = "Detect Cisco Smart Install service exposed on port 4786 (CVE-2018-0171)"
    category = PluginCategory.services
    severity = Severity.high
    cve_ids = ["CVE-2018-0171"]
    cvss_vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ports = [4786]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        for port in host.ports:
            if port.number != 4786 or port.state != "open":
                continue
            vulnerable = await asyncio.get_event_loop().run_in_executor(
                None, self._probe_smart_install, host.ip
            )
            if vulnerable:
                return [FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="Cisco Smart Install Service Exposed (CVE-2018-0171)",
                    description=(
                        "The Cisco Smart Install protocol is accessible on port 4786/tcp. "
                        "An unauthenticated attacker can abuse this service to retrieve "
                        "the device's startup configuration (containing credentials), "
                        "replace the configuration, or trigger a reload — without any "
                        "authentication. This has been exploited by threat actors to "
                        "exfiltrate network configurations at scale."
                    ),
                    evidence=f"Cisco Smart Install protocol banner received on {host.ip}:4786",
                    remediation=(
                        "Disable Smart Install if not required: 'no vstack' in IOS config. "
                        "If Smart Install is needed, restrict access via ACL to the director "
                        "IP only. Apply Cisco advisory cisco-sa-20180328-smi2 patches."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2018-0171",
                        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2",
                    ],
                    port_number=4786,
                    protocol="tcp",
                )]
        return []

    def _probe_smart_install(self, ip: str) -> bool:
        """Send a Smart Install type 0x00000001 (show version request) and check response."""
        # Minimal Smart Install packet header
        smi_packet = (
            b"\x00\x00\x00\x01"  # type: SMI_MSG_TYPE_GETIMAGE
            b"\x00\x00\x00\x00"  # message length field
        )
        try:
            sock = socket.create_connection((ip, 4786), timeout=8)
            sock.sendall(smi_packet)
            resp = sock.recv(64)
            sock.close()
            # Any response longer than 4 bytes indicates an SMI service
            return len(resp) >= 4
        except (ConnectionRefusedError, OSError):
            return False
        except Exception as exc:
            logger.debug("Cisco SMI probe failed for %s: %s", ip, exc)
            return False
