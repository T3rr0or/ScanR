"""Heartbleed (CVE-2014-0160) detection plugin.

Sends a malformed TLS heartbeat request and checks if the server returns
more data than was sent — the hallmark of the vulnerability.
This is a safe, read-only probe with no exploitation.
"""
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
SSL_PORTS = [443, 8443, 993, 995, 465]


# Minimal TLS record header (unused at module level — actual hello built inline)
_CLIENT_HELLO = bytes.fromhex(
    "16030100dc"  # TLS record: handshake, TLS 1.0, length
    "010000d8"    # ClientHello
    "030200"      # version + padding (even digits)
)

# Heartbeat request: type=1 (request), payload_length=0x4000 (overread)
_HEARTBEAT_REQ = bytes([
    0x18, 0x03, 0x02,  # TLS record: heartbeat, TLS 1.2
    0x00, 0x03,        # record length = 3
    0x01,              # HeartbeatMessageType: request
    0x40, 0x00,        # payload_length = 16384 (overread)
])


class HeartbleedPlugin(PluginBase):
    id = "ssl_tls.heartbleed"
    name = "Heartbleed (CVE-2014-0160)"
    description = "Test for OpenSSL Heartbleed vulnerability"
    category = PluginCategory.ssl_tls
    severity = Severity.critical
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    cve_ids = ["CVE-2014-0160"]
    ports = SSL_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in SSL_PORTS or port.state != "open":
                continue
            vulnerable = await self._test_heartbleed(host.ip, port.number)
            if vulnerable:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="Heartbleed Vulnerability Detected (CVE-2014-0160)",
                    description=(
                        "The server is vulnerable to the Heartbleed bug in OpenSSL. "
                        "An attacker can read up to 64KB of server memory per request, "
                        "potentially exposing private keys, session tokens, and credentials."
                    ),
                    evidence=f"Server on {host.ip}:{port.number} returned heartbeat response indicating memory overread",
                    remediation="Upgrade OpenSSL to 1.0.1g or later. Rotate all private keys and certificates after patching.",
                    references=["https://heartbleed.com", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
                    cvss_vector=self.cvss_vector,
                    cve_ids=self.cve_ids,
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _test_heartbleed(self, ip: str, port: int) -> bool:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._test_sync, ip, port)

    def _test_sync(self, ip: str, port: int) -> bool:
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            sock.settimeout(5)
            # Send minimal ClientHello to initiate TLS
            hello = (
                b"\x16\x03\x01\x00\xdc\x01\x00\x00\xd8\x03\x02" +
                b"\x00" * 32 +  # random
                b"\x00" +       # session id length
                b"\x00\x66" +   # cipher suites length = 102
                b"\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38\x00\x88\x00\x87"
                b"\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b"
                b"\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0\x1f"
                b"\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e"
                b"\xc0\x04\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02"
                b"\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08"
                b"\x00\x06\x00\x03\x00\xff" +
                b"\x01" +       # compression methods length
                b"\x00" +       # no compression
                b"\x00\x49" +   # extensions length
                # heartbeat extension
                b"\xff\x01\x00\x01\x00" +
                b"\x00\x0f\x00\x01\x01"
            )
            sock.send(hello)
            # Wait for ServerHello
            data = b""
            for _ in range(10):
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 2000:
                        break
                except socket.timeout:
                    break

            # Send heartbeat request
            hb = b"\x18\x03\x02\x00\x03\x01\x40\x00"
            sock.send(hb)

            # Read response — vulnerable servers return 16KB+
            resp = b""
            try:
                for _ in range(5):
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if resp[0:1] == b"\x18":  # heartbeat response type
                        # Parse heartbeat: vulnerable = payload > 3 bytes
                        if len(resp) > 7:
                            payload_len = struct.unpack("!H", resp[6:8])[0]
                            return payload_len > 3
                        break
            except Exception:
                pass
            sock.close()
            return False
        except Exception:
            return False
