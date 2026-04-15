from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

SSL_PORTS = [443, 8443, 993, 995, 465, 636, 5986]


class CertInspectorPlugin(PluginBase):
    id = "ssl_tls.cert_inspector"
    name = "SSL Certificate Inspector"
    description = "Check certificate expiry, weak signature algorithms, and CN mismatch"
    category = PluginCategory.ssl_tls
    severity = Severity.medium
    ports = SSL_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in SSL_PORTS or port.state != "open":
                continue
            cert_info = await self._get_cert(host.ip, port.number)
            if not cert_info:
                continue
            findings.extend(self._analyze_cert(cert_info, host.ip, port.number))
        return findings

    async def _get_cert(self, ip: str, port: int) -> dict | None:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_cert_sync, ip, port)

    def _get_cert_sync(self, ip: str, port: int) -> dict | None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with ctx.wrap_socket(
                __import__("socket").create_connection((ip, port), timeout=5),
                server_hostname=ip,
            ) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                return {"cert": cert, "der": der, "cipher": cipher}
        except Exception as exc:
            logger.debug("Cert fetch failed %s:%d: %s", ip, port, exc)
            return None

    def _analyze_cert(self, info: dict, ip: str, port: int) -> list[FindingData]:
        findings = []
        cert = info["cert"]
        now = datetime.now(tz=timezone.utc)

        # Check expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (not_after - now).days
                if days_left < 0:
                    findings.append(FindingData(
                        plugin_id=self.id,
                        severity=Severity.critical,
                        title=f"SSL Certificate Expired ({abs(days_left)} days ago)",
                        description=f"The SSL certificate on port {port} has expired.",
                        evidence=f"Certificate expired: {not_after_str}",
                        remediation="Renew the SSL certificate immediately.",
                        port_number=port,
                        protocol="tcp",
                    ))
                elif days_left < 30:
                    findings.append(FindingData(
                        plugin_id=self.id,
                        severity=Severity.high,
                        title=f"SSL Certificate Expiring Soon ({days_left} days)",
                        description=f"The SSL certificate on port {port} expires in {days_left} days.",
                        evidence=f"Certificate expires: {not_after_str}",
                        remediation="Renew the SSL certificate before it expires.",
                        port_number=port,
                        protocol="tcp",
                    ))
            except Exception:
                pass

        # Check weak signature algorithm
        sig_alg = cert.get("signatureAlgorithm", "")
        if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title="Weak Certificate Signature Algorithm",
                description=f"Certificate uses weak signature algorithm: {sig_alg}",
                evidence=f"Signature algorithm: {sig_alg}",
                remediation="Replace the certificate with one using SHA-256 or stronger.",
                port_number=port,
                protocol="tcp",
            ))

        return findings
