"""ICMP information plugin.

Documents ICMP echo response behavior — whether the host responds to ping
and its ICMP TTL (useful for OS fingerprinting).
"""
from __future__ import annotations

import logging
import socket
import struct
import time
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class IcmpInfoPlugin(PluginBase):
    id = "network.icmp_info"
    name = "ICMP Information"
    description = "Document ICMP echo response and TTL for OS fingerprint hints"
    category = PluginCategory.network
    severity = Severity.info
    ports = None  # not port-specific

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        result = self._icmp_probe(host.ip)
        if result is None:
            return []
        ttl, rtt_ms = result
        os_hint = _ttl_os_hint(ttl)
        return [FindingData(
            plugin_id=self.id,
            severity=Severity.info,
            title="ICMP Echo Response",
            description="Host responds to ICMP echo requests (ping). TTL value provides OS fingerprint hints.",
            evidence=f"ICMP echo reply from {host.ip}: TTL={ttl} ({os_hint}), RTT={rtt_ms:.1f}ms",
            remediation="Consider filtering ICMP echo requests at the firewall perimeter to reduce host enumeration.",
            port_number=None,
            protocol="icmp",
        )]

    def _icmp_probe(self, ip: str) -> tuple[int, float] | None:
        """Send a raw ICMP echo request and return (ttl, rtt_ms) or None."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(1)

            # ICMP echo request: type=8, code=0, checksum, id, seq, data
            icmp_id = 0xABCD
            icmp_seq = 1
            header = struct.pack("!BBHHH", 8, 0, 0, icmp_id, icmp_seq)
            data = b"ScanR-probe"
            checksum = _icmp_checksum(header + data)
            packet = struct.pack("!BBHHH", 8, 0, checksum, icmp_id, icmp_seq) + data

            t0 = time.monotonic()
            sock.sendto(packet, (ip, 0))
            resp, addr = sock.recvfrom(1024)
            rtt = (time.monotonic() - t0) * 1000

            # IP header is 20 bytes; ICMP starts at offset 20
            if len(resp) < 28:
                return None
            ttl = resp[8]  # TTL field in IP header
            icmp_type = resp[20]
            if icmp_type == 0:  # echo reply
                return ttl, rtt
            return None
        except PermissionError:
            # No raw socket permission — skip silently
            return None
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass


def _icmp_checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _ttl_os_hint(ttl: int) -> str:
    if ttl <= 64:
        return "Linux/macOS (TTL≤64)"
    if ttl <= 128:
        return "Windows (TTL≤128)"
    if ttl <= 255:
        return "Network device / Solaris (TTL≤255)"
    return "Unknown"
