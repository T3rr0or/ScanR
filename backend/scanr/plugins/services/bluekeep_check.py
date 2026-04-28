"""BlueKeep CVE-2019-0708 detection via RDP MS_T120 channel probe (rdpscan technique)."""
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


class BluekeepCheckPlugin(PluginBase):
    id = "services.bluekeep_check"
    name = "BlueKeep CVE-2019-0708 RDP Vulnerability"
    description = "Detect BlueKeep RDP vulnerability using MS_T120 channel probe (detection only)"
    category = PluginCategory.services
    severity = Severity.critical
    cve_ids = ["CVE-2019-0708"]
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    ports = [3389]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number != 3389 or port.state != "open":
                continue
            loop = asyncio.get_event_loop()
            vulnerable = await loop.run_in_executor(None, self._rdp_sync, host.ip, port.number)
            if vulnerable:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="BlueKeep CVE-2019-0708 RDP Vulnerability Detected",
                    description=(
                        "The host appears vulnerable to BlueKeep (CVE-2019-0708), a critical "
                        "pre-authentication use-after-free vulnerability in Windows Remote Desktop "
                        "Services. The server accepted the MS_T120 channel in the MCS Connect Initial "
                        "PDU without disconnecting, which is the rdpscan detection fingerprint. "
                        "An unauthenticated attacker can exploit this to achieve remote code execution "
                        "with SYSTEM privileges. This vulnerability is wormable and affects "
                        "Windows 7, Windows Server 2008 R2, and earlier systems."
                    ),
                    evidence=(
                        f"RDP on {host.ip}:3389 responded with MCS Connect Response (accepted "
                        "MS_T120 channel) instead of Disconnect Provider Ultimatum — "
                        "BlueKeep fingerprint confirmed"
                    ),
                    remediation=(
                        "Apply Microsoft Security Update KB4499175. "
                        "Enable Network Level Authentication (NLA) to add pre-authentication. "
                        "Block RDP (TCP 3389) from the internet and restrict to VPN only. "
                        "Upgrade to Windows 10 / Server 2019 which are not affected."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
                    ],
                    cvss_vector=self.cvss_vector,
                    cve_ids=self.cve_ids,
                    port_number=3389,
                    protocol="tcp",
                ))
        return findings

    def _rdp_sync(self, ip: str, port: int) -> bool:
        try:
            sock = socket.create_connection((ip, port), timeout=5)

            # Step 1: X.224 Connection Request (TPKT + X.224 CR)
            # Cookie-less minimal CR PDU
            x224_cr = (
                b"\x03\x00\x00\x13"   # TPKT: version=3, reserved=0, length=19
                b"\x0e"               # X.224: TPDU length indicator = 14
                b"\xe0"               # X.224: Connection Request (CR) TPDU type
                b"\x00\x00"           # DST-REF
                b"\x00\x00"           # SRC-REF
                b"\x00"               # CLASS OPTION
                b"\x01\x00\x08\x00"   # RDP Negotiation Request type=1, flags=0, length=8
                b"\x03\x00\x00\x00"   # requestedProtocols: TLS + CredSSP (we want plain RDP fallback)
            )
            sock.sendall(x224_cr)
            x224_resp = sock.recv(1024)

            if not x224_resp or len(x224_resp) < 6:
                sock.close()
                return False

            # X.224 Connection Confirm is TPDU type 0xd0
            if x224_resp[5] != 0xd0:
                sock.close()
                return False

            # Step 2: MCS Connect Initial containing the MS_T120 channel (0x03ef / 1007)
            # This is the BlueKeep probe: patched hosts send Disconnect Provider Ultimatum
            # when they see MS_T120 in the channel list; vulnerable hosts accept it.
            #
            # GCC Conference Create Request embedded in MCS Connect Initial.
            # Channel 0x03ef (1007) is the MS_T120 channel used by BlueKeep.
            # The payload is derived from the rdpscan / CVE-2019-0708 PoC scanner.
            mcs_ci = bytes.fromhex(
                # TPKT header: version=3, reserved=0, length=0x0130=304
                "0300012e"
                # X.224 Data TPDU: LI=2, DT=0xf0, EOT=0x80
                "02f08000"
                # MCS Connect-Initial BER tag (0x7f65) + length
                "7f655b"
                # callingDomainSelector: 0x04 0x01 0x01
                "0401 01"
                # calledDomainSelector:  0x04 0x01 0x01
                "0401 01"
                # upwardFlag: TRUE  0x01 0x01 0xff
                "0101 ff"
                # targetParameters SEQUENCE
                "3019"
                "02012202010202010002010102010002010102020fff02010 2"
                # minimumParameters SEQUENCE
                "3019"
                "020101020101020101020101020100020101020204200201 02"
                # maximumParameters SEQUENCE
                "3019"
                "0201ff0202fc170201ff020101020100020101020 2ffff020102"
                # userData: GCC Conference Create Request with channel list including MS_T120
                "04820094"
                # GCC Conference Create Request header
                "00 05 00 14 7c 00 01"
                "81 88"
                # H.221 key: "Duca"
                "00 08 00 10 00 01 c0 00 44 75 63 61"
                "81 7c"
                # CS_CORE (0xc001): length=216
                "01 c0 d8 00"
                "04 00 08 00"  # version: RDP 5.0
                "00 04 00 03"  # desktopWidth=1024, desktopHeight=768
                "01 ca"        # colorDepth: 8bpp
                "03 aa"        # SASSequence
                "09 04 00 00"  # keyboardLayout: English US
                "28 0a 00 00"  # clientBuild
                # clientName (32 bytes, UTF-16LE padded)
                "45 00 4c 00 54 00 4f 00 4e 00 2d 00 45 00 37 00"
                "42 00 46 00 51 00 52 00 00 00 00 00 00 00 00 00"
                "04 00 00 00"  # keyboardType: IBM enhanced 101/102
                "00 00 00 00"  # keyboardSubType
                "0c 00 00 00"  # keyboardFunctionKey
                # imeFileName (64 bytes, zeroed)
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                "01 ca"        # postBeta2ColorDepth
                "00 00"        # clientProductId
                "00 00 00 00"  # serialNumber
                "18 00"        # highColorDepth: 24bpp
                "07 00"        # supportedColorDepths
                "01 00"        # earlyCapabilityFlags
                # clientDigProductId (64 bytes, zeroed)
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                "00"           # connectionType
                "00"           # pad1octet
                "00 00 00 00"  # serverSelectedProtocol
                # CS_CLUSTER (0xc004): length=12
                "04 c0 0c 00"
                "0d 00 00 00"  # flags: redirectedSessionId support
                "00 00 00 00"
                # CS_SECURITY (0xc002): length=12
                "02 c0 0c 00"
                "1b 00 00 00"  # encryptionMethods: 40+56+128bit
                "00 00 00 00"
                # CS_NET (0xc003): channel list including MS_T120
                "03 c0 34 00"  # length=52 → 4 channels × 12 bytes each + 4 byte count
                "04 00 00 00"  # channelCount = 4
                # Channel 1: rdpdr
                "72 64 70 64 72 00 00 00"  # name: "rdpdr\0\0\0"
                "80 00 00 00"              # options: INITIALIZED | COMPRESS_RDP
                # Channel 2: rdpsnd
                "72 64 70 73 6e 64 00 00"  # name: "rdpsnd\0\0"
                "00 00 00 00"
                # Channel 3: drdynvc
                "64 72 64 79 6e 76 63 00"  # name: "drdynvc\0"
                "80 00 00 00"
                # Channel 4: MS_T120 — the BlueKeep probe channel (name must be MS_T120)
                "4d 53 5f 54 31 32 30 00"  # name: "MS_T120\0"
                "00 00 08 00"              # options
            )

            # bytes.fromhex() already strips whitespace (Python 3.7+); mcs_ci is already bytes
            mcs_ci_bytes = mcs_ci

            # Fix TPKT length field (bytes 2-3, big-endian)
            total_len = len(mcs_ci_bytes)
            mcs_ci_bytes = mcs_ci_bytes[:2] + total_len.to_bytes(2, "big") + mcs_ci_bytes[4:]

            sock.sendall(mcs_ci_bytes)
            resp = sock.recv(4096)
            sock.close()

            if not resp or len(resp) < 8:
                return False

            # Skip TPKT (4 bytes) and X.224 DT header (3 bytes) to get at MCS PDU
            # Look for MCS Connect-Response BER tag 0x7f66 → server accepted → vulnerable
            # Look for MCS Disconnect Provider Ultimatum tag 0x21 → patched
            if b"\x7f\x66" in resp:
                return True
            if b"\x21\x80" in resp or b"\x21\x00" in resp:
                return False

            return False

        except Exception:
            logger.debug("bluekeep_check: probe failed for %s:%d", ip, port, exc_info=True)
            return False
