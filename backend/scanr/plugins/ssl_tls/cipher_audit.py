from __future__ import annotations

import asyncio
import logging
import ssl
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

SSL_PORTS = [443, 8443, 993, 995, 465, 636, 5986]

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ADH", "AECDH",
    "RC4-SHA", "RC4-MD5", "DES-CBC-SHA", "EXP",
}


class CipherAuditPlugin(PluginBase):
    id = "ssl_tls.cipher_audit"
    name = "Weak Cipher Suite Detection"
    description = "Detect RC4, DES, NULL, and export cipher suites"
    category = PluginCategory.ssl_tls
    severity = Severity.high
    ports = SSL_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in SSL_PORTS or port.state != "open":
                continue
            weak = await self._check_ciphers(host.ip, port.number)
            if weak:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="Weak SSL/TLS Cipher Suites Supported",
                    description=f"The server on port {port.number} supports weak cipher suites that could allow decryption of traffic.",
                    evidence=f"Weak ciphers detected: {', '.join(weak)}",
                    remediation="Disable weak cipher suites. Configure the server to use only TLS 1.2+ with strong ciphers (AES-GCM, ChaCha20-Poly1305).",
                    references=["https://ciphersuite.info", "https://www.ssllabs.com/projects/best-practices/"],
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _check_ciphers(self, ip: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._check_sync, ip, port)

    def _check_sync(self, ip: str, port: int) -> list[str]:
        weak_found = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with ctx.wrap_socket(
                __import__("socket").create_connection((ip, port), timeout=5),
                server_hostname=ip,
            ) as ssock:
                cipher_name, _, _ = ssock.cipher()
                for weak in WEAK_CIPHERS:
                    if weak in cipher_name.upper():
                        weak_found.append(cipher_name)
        except Exception:
            pass
        return weak_found
