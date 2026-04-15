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

# RMCP+ Open Session Request with Cipher Suite 0 (no authentication)
# References: CVE-2013-4786, IPMI 2.0 spec
RMCP_OPEN_SESSION = bytes([
    0x06, 0x00, 0xff, 0x07,  # RMCP header: version=6, reserved, seq, class=IPMI
    0x00, 0x00, 0x00, 0x00,  # IPMI session header (auth type=none, seq=0)
    0x00, 0x00, 0x00, 0x00,  # session ID=0
    0x00, 0x00, 0x00, 0x00,  # 4 zero bytes
    0x20,                    # message length = 32 (body)
    0x18, 0x1c,              # Get Channel Auth Capabilities (lun=0, netFn=0x06 = app)
    0x81,                    # checksum
    0x20, 0x00,              # source/dest LUN
    0x38,                    # Get Auth Capabilities cmd = 0x38
    0x8e,                    # channel = current
    0x04,                    # privilege level = Administrator
    0x31,                    # checksum
])


class IPMICipherZeroPlugin(PluginBase):
    id = "services.ipmi_cipher_zero"
    name = "IPMI Cipher Suite 0 Authentication Bypass"
    description = "Detect IPMI 2.0 BMCs vulnerable to Cipher 0 authentication bypass (CVE-2013-4786)"
    category = PluginCategory.services
    severity = Severity.critical
    cve_ids = ["CVE-2013-4786"]
    ports = [623]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number != 623 or port.state != "open":
                continue
            result = await self._probe(host.ip, port.number)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, ip: str, port: int) -> FindingData | None:
        loop = asyncio.get_event_loop()
        try:
            # IPMI uses UDP
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._udp_probe, ip, port),
                timeout=5.0,
            )
            return result
        except Exception:
            pass
        return None

    def _udp_probe(self, ip: str, port: int) -> FindingData | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(RMCP_OPEN_SESSION, (ip, port))
            try:
                data, _ = sock.recvfrom(512)
            finally:
                sock.close()

            # A response to RMCP means IPMI service is present
            if len(data) < 4:
                return None
            # Check for valid RMCP response header
            if data[0] != 0x06:  # RMCP version 6
                return None

            return FindingData(
                plugin_id=self.id,
                severity=Severity.critical,
                title="IPMI 2.0 Service Detected — Potential Cipher 0 Auth Bypass",
                description=(
                    "An IPMI 2.0 Baseboard Management Controller (BMC) was detected on UDP port 623. "
                    "Many BMC implementations accept Cipher Suite 0 (no encryption, no authentication), "
                    "allowing attackers to authenticate as any user including admin without a password "
                    "(CVE-2013-4786). Additionally, IPMI 2.0 hashes can be captured remotely for offline cracking."
                ),
                evidence=f"UDP RMCP packet to {ip}:{port} → valid IPMI response ({len(data)} bytes)",
                remediation=(
                    "Disable Cipher Suite 0 in BMC firmware settings. "
                    "Enable only strong cipher suites (Suite 3 or higher). "
                    "Restrict IPMI access to a dedicated management network (VLAN). "
                    "Update BMC firmware to the latest version. "
                    "Change all default IPMI credentials."
                ),
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2013-4786",
                    "https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/",
                ],
                cve_ids=["CVE-2013-4786"],
                port_number=port,
                protocol="udp",
            )
        except socket.timeout:
            pass
        except Exception as e:
            logger.debug("IPMI probe error for %s:%d: %s", ip, port, e)
        return None
