"""MS17-010 EternalBlue detection via Trans2 fingerprint (more accurate than basic SMBv1 negotiate)."""
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


class Ms17010CheckPlugin(PluginBase):
    id = "services.ms17_010_check"
    name = "MS17-010 EternalBlue (Precise Check)"
    description = "Detect MS17-010 EternalBlue using Trans2 fingerprint technique"
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
            loop = asyncio.get_running_loop()
            vulnerable = await loop.run_in_executor(None, self._smb_sync, host.ip)
            if vulnerable:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="MS17-010 EternalBlue SMB Vulnerability Detected (Trans2 Check)",
                    description=(
                        "The host is vulnerable to MS17-010 (EternalBlue). "
                        "This was confirmed using the Trans2 fingerprint technique: the server "
                        "returned STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) in response to a "
                        "malformed Trans2 request, which is the signature of an unpatched SMBv1 "
                        "implementation. This vulnerability was exploited by WannaCry and NotPetya "
                        "ransomware and allows unauthenticated remote code execution as SYSTEM."
                    ),
                    evidence=(
                        f"SMB Trans2 probe on {host.ip}:445 returned "
                        "STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) — EternalBlue fingerprint confirmed"
                    ),
                    remediation=(
                        "Apply Microsoft Security Bulletin MS17-010 immediately. "
                        "Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false. "
                        "Block TCP port 445 at the perimeter firewall. "
                        "If patching is delayed, isolate the host from the network."
                    ),
                    references=[
                        "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
                        "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                        "https://nvd.nist.gov/vuln/detail/CVE-2017-0145",
                        "https://nvd.nist.gov/vuln/detail/CVE-2017-0146",
                    ],
                    cvss_vector=self.cvss_vector,
                    cve_ids=self.cve_ids,
                    port_number=445,
                    protocol="tcp",
                ))
        return findings

    def _smb_sync(self, ip: str) -> bool:
        try:
            # SMBv1 Negotiate Request
            smb1_negotiate = (
                b"\x00\x00\x00\x54"       # NBT session length
                b"\xff\x53\x4d\x42"       # SMB1 magic (ffSMB)
                b"\x72"                   # command: Negotiate Protocol
                b"\x00\x00\x00\x00"       # NT status
                b"\x18"                   # flags
                b"\x01\x28"               # flags2
                + b"\x00" * 12 +          # reserved (12 bytes)
                b"\xff\xff"               # TID
                b"\x00\x00"               # PID
                b"\x00\x00"               # UID
                b"\x00\x00"               # MID
                b"\x00"                   # word count = 0
                b"\x31\x00"               # byte count = 49
                b"\x02NT LM 0.12\x00"     # dialect 0
                b"\x02SMB 2.002\x00"      # dialect 1
                b"\x02SMB 2.???\x00"      # dialect 2
            )

            sock = socket.create_connection((ip, 445), timeout=5)
            sock.sendall(smb1_negotiate)
            resp = sock.recv(1024)

            # Verify server responded with SMBv1 magic
            if len(resp) < 13 or resp[4:8] != b"\xffSMB":
                sock.close()
                return False

            # Must be STATUS_SUCCESS — server agreed to SMBv1
            status = struct.unpack_from("<I", resp, 9)[0]
            if status != 0x00000000:
                sock.close()
                return False

            # Extract UID from negotiate response (offset 28, 2 bytes LE)
            uid = struct.unpack_from("<H", resp, 28)[0] if len(resp) > 30 else 0

            # Trans2 OPEN2 with malformed parameters — EternalBlue fingerprint probe.
            # Vulnerable hosts return STATUS_INSUFF_SERVER_RESOURCES (0xC0000205).
            # Patched hosts return STATUS_NOT_SUPPORTED or disconnect.
            trans2 = (
                b"\x00\x00\x00\x4f"          # NBT length = 79
                b"\xff\x53\x4d\x42"          # SMB1 magic
                b"\x25"                      # command: Trans2
                b"\x00\x00\x00\x00"          # NT status
                b"\x18\x07\xc0"              # flags, flags2
                + b"\x00" * 12 +             # reserved
                b"\xff\xff"                  # TID
                + struct.pack("<H", uid) +   # UID from negotiate
                b"\x00\x00"                  # MID
                b"\x0f"                      # word count = 15
                b"\x0f\x00\x00\x00"          # total param count, total data count
                b"\x01\x00\x00\x00"          # max param, max data
                b"\x00\x00\x00\x00"          # max setup, reserved
                b"\x00\x00\x00\x00"          # flags, timeout
                b"\x00\x00\x00\x00"          # reserved, param count
                b"\x00\x00\x00\x00"          # param offset, data count
                b"\x00\x00\x00\x00"          # data offset, setup count
                b"\x00\x00\x03\x00"          # reserved, sub-command (OPEN2)
            )
            sock.sendall(trans2)
            resp2 = sock.recv(1024)
            sock.close()

            if len(resp2) < 13:
                return False

            status2 = struct.unpack_from("<I", resp2, 9)[0]
            # STATUS_INSUFF_SERVER_RESOURCES = EternalBlue vulnerable signature
            return status2 == 0xC0000205

        except Exception:
            logger.debug("ms17_010_check: probe failed for %s", ip, exc_info=True)
            return False
