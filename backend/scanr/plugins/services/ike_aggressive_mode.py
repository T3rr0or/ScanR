"""IKE Aggressive Mode detection.

IKE Aggressive Mode allows an attacker to capture the VPN gateway's
hashed pre-shared key (PSK) during the negotiation, which can then be
cracked offline via dictionary attack.
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class IkeAggressiveModePlugin(PluginBase):
    id = "services.ike_aggressive_mode"
    name = "IKE Aggressive Mode Enabled"
    description = "Check if IKEv1 VPN gateway responds to Aggressive Mode, exposing the PSK hash"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [500]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        for port in host.ports:
            if port.number != 500 or port.state != "open":
                continue
            vulnerable = await asyncio.get_event_loop().run_in_executor(
                None, self._probe_aggressive_mode, host.ip
            )
            if vulnerable:
                return [FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="IKEv1 Aggressive Mode Enabled on VPN Gateway",
                    description=(
                        "The VPN gateway responds to IKEv1 Aggressive Mode negotiation. "
                        "In Aggressive Mode, the gateway sends its hashed pre-shared key "
                        "(PSK) to any client that initiates a negotiation. An attacker can "
                        "capture this hash and crack it offline to obtain the VPN PSK, "
                        "potentially allowing unauthorized VPN access."
                    ),
                    evidence=f"IKEv1 Aggressive Mode negotiation accepted on {host.ip}:500/udp",
                    remediation=(
                        "Disable IKEv1 Aggressive Mode on the VPN gateway and migrate to "
                        "IKEv2 which does not support Aggressive Mode. If IKEv1 must be "
                        "retained, use certificates instead of PSK authentication."
                    ),
                    references=[
                        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-1623",
                        "https://www.securityfocus.com/bid/7423",
                    ],
                    port_number=500,
                    protocol="udp",
                )]
        return []

    def _probe_aggressive_mode(self, ip: str) -> bool:
        """Send an IKEv1 Aggressive Mode initiation packet and check for a non-rejection response."""
        initiator_spi = os.urandom(8)
        # Build minimal IKEv1 Aggressive Mode packet (Exchange Type 4)
        # SA payload with a simple transform
        sa_payload = self._build_sa_payload()
        key_exchange = b"\x00" * 96  # dummy 768-bit DH public key (group 1)
        nonce = os.urandom(16)
        id_payload = socket.inet_aton(ip)  # use target IP as ID

        # Pack payloads: SA + KE + Nonce + ID
        # Next-payload chaining: SA=1, KE=4, Nonce=10, ID=5
        ke_data = struct.pack("!HH", 0, 0) + key_exchange  # DH group=0 (placeholder), pad
        nonce_data = nonce
        id_data = struct.pack("!BBH", 1, 0, 0) + id_payload  # ID_IPV4_ADDR

        def payload(next_type: int, data: bytes) -> bytes:
            return bytes([next_type, 0]) + struct.pack("!H", len(data) + 4) + data

        payloads = (
            payload(4, sa_payload) +
            payload(10, ke_data) +
            payload(5, nonce_data) +
            payload(0, id_data)
        )

        isakmp = (
            initiator_spi +
            b"\x00" * 8 +  # responder SPI (0)
            bytes([1]) +    # next payload = SA (1)
            bytes([0x10]) + # version 1.0
            bytes([0x04]) + # exchange type = Aggressive (4)
            bytes([0x00]) + # flags
            b"\x00\x00\x00\x00" +  # message ID
            struct.pack("!I", 28 + len(payloads)) +
            payloads
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(isakmp, (ip, 500))
            data, _ = sock.recvfrom(1024)
            sock.close()
            # Any response (other than ICMP unreachable caught as exception) indicates
            # the gateway is processing our Aggressive Mode packet.
            # A proper Aggressive Mode response will have exchange type 4 at offset 18.
            if len(data) > 18:
                exchange_type = data[18]
                return exchange_type == 4
            return len(data) > 0
        except (socket.timeout, OSError):
            return False
        except Exception as exc:
            logger.debug("IKE probe failed for %s: %s", ip, exc)
            return False

    def _build_sa_payload(self) -> bytes:
        import struct
        # Minimal SA payload: one proposal with one transform (DES-CBC + MD5 + group 1)
        transform = (
            struct.pack("!BB", 0, 1) +   # last transform, transform number
            struct.pack("!H", 24) +       # transform length
            struct.pack("!BBH", 1, 0, 0) + # transform ID (KEY_IKE=1), reserved
            # Attributes: encryption DES, hash MD5, auth PSK, group 1, lifetime
            b"\x80\x01\x00\x01" +  # encryption: DES (1)
            b"\x80\x02\x00\x01" +  # hash: MD5 (1)
            b"\x80\x03\x00\x01" +  # auth: PSK (1)
            b"\x80\x04\x00\x01"    # DH group 1
        )
        proposal = (
            struct.pack("!BB", 0, 1) +  # last proposal, proposal number
            struct.pack("!H", 8 + len(transform)) +
            struct.pack("!BBH", 1, 0, 0) +  # protocol ISAKMP=1, SPI size=0, num transforms=0
            b"\x01" +  # 1 transform
            transform
        )
        return struct.pack("!I", 1) + proposal  # DOI=1 (IPSEC) + proposal

