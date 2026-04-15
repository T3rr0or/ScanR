"""EternalBlue (MS17-010 / CVE-2017-0144) detection.

Detection-only — checks for the vulnerable SMB dialect support without
sending exploit code. Safe, read-only probe.
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


class SmbVulnsPlugin(PluginBase):
    id = "services.smb_vulns"
    name = "EternalBlue (MS17-010)"
    description = "Check for EternalBlue SMB vulnerability (detection only)"
    category = PluginCategory.services
    severity = Severity.critical
    cve_ids = ["CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146"]
    cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ports = [445]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number != 445 or port.state != "open":
                continue
            vulnerable = await self._check_ms17010(host.ip)
            if vulnerable:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="MS17-010 EternalBlue SMB Vulnerability Detected",
                    description=(
                        "The host appears vulnerable to EternalBlue (MS17-010). "
                        "This critical SMB vulnerability was exploited by WannaCry and NotPetya ransomware. "
                        "An unauthenticated attacker can achieve remote code execution with SYSTEM privileges."
                    ),
                    evidence=f"SMB on {host.ip}:445 responded to MS17-010 detection probe",
                    remediation=(
                        "Apply Microsoft Security Bulletin MS17-010 immediately. "
                        "If patching is not immediately possible, disable SMBv1 and block port 445 at the firewall."
                    ),
                    references=[
                        "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
                        "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                    ],
                    cvss_vector=self.cvss_vector,
                    cve_ids=self.cve_ids,
                    port_number=445,
                    protocol="tcp",
                ))
        return findings

    async def _check_ms17010(self, ip: str) -> bool:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._smb_sync, ip)

    def _smb_sync(self, ip: str) -> bool:
        try:
            # SMB1 negotiate packet (using + for b"..." * N expressions)
            smb1_negotiate = (
                b"\x00\x00\x00\x54"      # NetBIOS session
                b"\xff\x53\x4d\x42"      # SMB1 magic (ffSMB)
                b"\x72"                  # command: negotiate
                b"\x00\x00\x00\x00"      # status
                b"\x18"                  # flags
                b"\x01\x28"              # flags2
                + b"\x00" * 12 +         # reserved
                b"\xff\xff"              # TID
                b"\x00\x00"              # PID
                b"\x00\x00"              # UID
                b"\x00\x00"              # MID
                b"\x00"                  # word count
                b"\x31\x00"              # byte count
                b"\x02NT LM 0.12\x00"   # dialect
                b"\x02SMB 2.002\x00"
                b"\x02SMB 2.???\x00"
            )
            sock = socket.create_connection((ip, 445), timeout=5)
            sock.send(smb1_negotiate)
            resp = sock.recv(1024)
            sock.close()
            # If the server responds to SMBv1 negotiate, it may be vulnerable
            # A patched server responds with STATUS_NOT_SUPPORTED for SMBv1
            if len(resp) > 4 and resp[4:8] == b"\xffSMB":
                status = resp[9:13]
                # STATUS_SUCCESS with SMBv1 negotiated = potentially vulnerable
                if status == b"\x00\x00\x00\x00":
                    return True
            return False
        except Exception:
            return False
