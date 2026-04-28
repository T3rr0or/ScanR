"""LLMNR (UDP/5355) and NBT-NS (UDP/137) poisoning attack surface detection on Windows hosts."""
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


class LlmnrNbnsCheckPlugin(PluginBase):
    id = "services.llmnr_nbns_check"
    name = "LLMNR/NBT-NS Poisoning Risk"
    description = (
        "Detect active LLMNR (UDP/5355) and NetBIOS Name Service (UDP/137) on Windows hosts, "
        "which can be abused by Responder to capture NTLMv2 credentials"
    )
    category = PluginCategory.services
    severity = Severity.medium
    # Trigger on SMB-enabled hosts (Windows indicator); actual probes are UDP
    ports = [445, 139]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        # Only check hosts that appear to be Windows (SMB ports open)
        smb_open = any(
            p.number in (445, 139) and p.state == "open"
            for p in host.ports
        )
        if not smb_open:
            return []

        loop = asyncio.get_running_loop()
        llmnr, nbns = await asyncio.gather(
            loop.run_in_executor(None, self._check_llmnr, host.ip),
            loop.run_in_executor(None, self._check_nbns, host.ip),
        )

        enabled = []
        if llmnr:
            enabled.append("LLMNR (UDP/5355)")
        if nbns:
            enabled.append("NBT-NS (UDP/137)")

        if not enabled:
            return []

        protocols = " and ".join(enabled)
        return [FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title="LLMNR/NBT-NS Enabled — Credential Poisoning Risk",
            description=(
                f"The host has {protocols} active. These legacy name resolution protocols "
                "broadcast queries on the local network and can be exploited by an attacker "
                "running Responder: when a client fails to resolve a hostname via DNS, it falls "
                "back to LLMNR/NBT-NS broadcasts. Responder answers those broadcasts with a "
                "spoofed response, causing the victim to authenticate to the attacker's machine "
                "and leaking NTLMv2 credential hashes that can be cracked offline or relayed."
            ),
            evidence=f"Host responded to UDP probe(s): {protocols}",
            remediation=(
                "Disable LLMNR via Group Policy: "
                "Computer Configuration → Administrative Templates → Network → DNS Client → "
                "Turn off Multicast Name Resolution → Enabled. "
                "Disable NetBIOS over TCP/IP: Network Adapter Properties → IPv4 Properties → "
                "Advanced → WINS tab → Disable NetBIOS over TCP/IP. "
                "Deploy DNSSEC and ensure internal DNS is reliable so name resolution "
                "does not fall back to these legacy protocols."
            ),
            references=[
                "https://www.blackhillsinfosec.com/responder-tips-tricks/",
                "https://attack.mitre.org/techniques/T1557/001/",
            ],
            port_number=None,
            protocol="udp",
        )]

    def _check_llmnr(self, ip: str) -> bool:
        """Send an LLMNR query for 'wpad' and return True if the host responds."""
        # LLMNR query packet: query for name "wpad", type A, class IN
        # Flags: standard query (QR=0, OPCODE=0, TC=0, C=0)
        query = (
            b"\xab\xcd"   # Transaction ID
            b"\x00\x00"   # Flags: standard query
            b"\x00\x01"   # QDCOUNT = 1
            b"\x00\x00"   # ANCOUNT = 0
            b"\x00\x00"   # NSCOUNT = 0
            b"\x00\x00"   # ARCOUNT = 0
            b"\x04wpad"   # QNAME label: length=4, "wpad"
            b"\x00"       # root label (end of name)
            b"\x00\x01"   # QTYPE: A
            b"\x00\x01"   # QCLASS: IN
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(query, (ip, 5355))
            data, _ = sock.recvfrom(512)
            sock.close()
            return len(data) > 0
        except Exception:
            logger.debug("llmnr_nbns_check: LLMNR probe failed for %s", ip, exc_info=True)
            return False

    def _check_nbns(self, ip: str) -> bool:
        """Send a NetBIOS Name Service query for 'WPAD' and return True if the host responds."""
        # NetBIOS name encoding: each character is split into two nibbles,
        # each nibble has 0x41 added. "WPAD" padded to 15 chars + null type byte = 16 chars.
        name = b"WPAD            "  # 16 bytes: WPAD + 12 spaces + type byte 0x00 in last slot
        encoded = b""
        for byte in name:
            encoded += bytes([((byte >> 4) & 0x0f) + 0x41])
            encoded += bytes([(byte & 0x0f) + 0x41])
        # The last two nibbles should encode the null type byte (0x00) → b"AA"
        # name[-1] == 0x20 (space) for workstation service; use as-is for generic probe

        nbns_query = (
            b"\xab\xcd"       # Transaction ID
            b"\x01\x10"       # Flags: query, B-node broadcast
            b"\x00\x01"       # QDCOUNT = 1
            b"\x00\x00"       # ANCOUNT = 0
            b"\x00\x00"       # NSCOUNT = 0
            b"\x00\x00"       # ARCOUNT = 0
            b"\x20"           # Name field length: 32 encoded bytes
            + encoded +       # 32-byte NetBIOS-encoded name
            b"\x00"           # Root label (end of name)
            b"\x00\x20"       # QTYPE: NB (NetBIOS name)
            b"\x00\x01"       # QCLASS: IN
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(nbns_query, (ip, 137))
            data, _ = sock.recvfrom(512)
            sock.close()
            return len(data) > 0
        except Exception:
            logger.debug("llmnr_nbns_check: NBT-NS probe failed for %s", ip, exc_info=True)
            return False
