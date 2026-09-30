"""POODLE/BEAST detection plugin.

POODLE (CVE-2014-3566): SSLv3 CBC cipher suites allow padding oracle attack.
BEAST  (CVE-2011-3389): TLS 1.0 CBC ciphers with RC4/block cipher modes.

Detects SSLv3 support and TLS 1.0 with block ciphers via ssl module probing.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.ssl_tls._ports import is_tls_port

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)
SSL_PORTS = [443, 8443, 993, 995, 465, 636]


class PoodleBeastPlugin(PluginBase):
    id = "ssl_tls.poodle_beast"
    name = "POODLE/BEAST Vulnerability Check"
    description = "Detect SSLv3 (POODLE) and TLS 1.0 CBC (BEAST) support"
    category = PluginCategory.ssl_tls
    severity = Severity.high
    cve_ids = ["CVE-2014-3566", "CVE-2011-3389"]
    ports = SSL_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        loop = asyncio.get_running_loop()
        for port in host.ports:
            if not is_tls_port(port):
                continue

            # POODLE: test SSLv3
            sslv3_ok = await loop.run_in_executor(None, self._test_protocol, host.ip, port.number, "SSLv3")
            if sslv3_ok:
                findings.append(
                    FindingData(
                        plugin_id=self.id,
                        severity=Severity.high,
                        title="POODLE — SSLv3 Enabled (CVE-2014-3566)",
                        description=(
                            "The server accepts SSLv3 connections. SSLv3 is vulnerable to POODLE, "
                            "which allows an active man-in-the-middle attacker to decrypt CBC-mode "
                            "ciphertext one byte at a time (padding oracle). SSLv3 was deprecated "
                            "by RFC 7568 in 2015."
                        ),
                        evidence=f"{host.ip}:{port.number} accepted SSLv3 handshake",
                        remediation="Disable SSLv3 entirely. Configure minimum TLS 1.2.",
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2014-3566", "https://poodle.io"],
                        cve_ids=["CVE-2014-3566"],
                        port_number=port.number,
                        protocol="tcp",
                    )
                )

            # BEAST: test TLS 1.0
            tls10_ok = await loop.run_in_executor(None, self._test_protocol, host.ip, port.number, "TLSv1-CBC")
            if tls10_ok:
                findings.append(
                    FindingData(
                        plugin_id=self.id,
                        severity=Severity.medium,
                        title="BEAST — TLS 1.0 CBC Supported (CVE-2011-3389)",
                        description=(
                            "The server accepts TLS 1.0. TLS 1.0 with CBC cipher suites is vulnerable "
                            "to the BEAST attack, which can allow an attacker to decrypt session cookies "
                            "in certain conditions. TLS 1.0 was deprecated by RFC 8996 in 2021."
                        ),
                        evidence=f"{host.ip}:{port.number} accepted a TLS 1.0 handshake using a CBC cipher suite",
                        remediation="Disable TLS 1.0 and 1.1. Use TLS 1.2 as the minimum version.",
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2011-3389"],
                        cve_ids=["CVE-2011-3389"],
                        port_number=port.number,
                        protocol="tcp",
                    )
                )

        return findings

    def _test_protocol(self, ip: str, port: int, protocol: str) -> bool:
        """Return True if the server accepts a connection with the given protocol."""
        # Modern OpenSSL may not expose or enable SSLv3. Never substitute TLS
        # 1.0 here: that would turn a TLS 1.0 handshake into a false POODLE hit.
        if protocol == "SSLv3" and not hasattr(ssl.TLSVersion, "SSLv3"):
            return False
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if protocol == "SSLv3":
                ctx.minimum_version = ssl.TLSVersion.SSLv3
                ctx.maximum_version = ssl.TLSVersion.SSLv3
            elif protocol in {"TLSv1", "TLSv1-CBC"}:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1
                if protocol == "TLSv1-CBC":
                    # Restrict the ClientHello to TLS 1.0 CBC suites. A
                    # successful handshake then proves the BEAST precondition.
                    ctx.set_ciphers(
                        "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:DES-CBC3-SHA"
                    )

            with socket.create_connection((ip, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip):
                    return True
        except Exception:
            return False
