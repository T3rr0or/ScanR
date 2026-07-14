"""SSL/TLS certificate inspection.

Connects with SNI set to the target's hostname (so name-based virtual hosts
present their real certificate), parses the DER certificate with ``cryptography``
and flags: expiry (expired / expiring soon), weak signature algorithms
(SHA-1/MD5), self-signed certificates, and hostname mismatch (the name isn't
covered by the certificate's SAN/CN).

Note: the previous implementation read ``ssl.getpeercert()`` with
``verify_mode=CERT_NONE``, which returns an *empty* dict — so no fields were ever
present and no findings were produced. We now parse the DER directly.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

SSL_PORTS = [443, 8443, 993, 995, 465, 636, 5986, 9443, 4443]


def _host_matches(name: str, patterns: set[str]) -> bool:
    """Whether ``name`` is covered by any cert name/SAN pattern (incl. wildcards)."""
    name = name.lower().rstrip(".")
    for pat in patterns:
        pat = pat.lower().rstrip(".")
        if pat == name:
            return True
        if pat.startswith("*."):
            # Wildcard matches exactly one left-most label.
            suffix = pat[1:]  # ".example.com"
            if name.endswith(suffix) and name[: -len(suffix)].count(".") == 0 and name != suffix[1:]:
                return True
    return False


class CertInspectorPlugin(PluginBase):
    id = "ssl_tls.cert_inspector"
    name = "SSL Certificate Inspector"
    description = "Check certificate expiry, weak signatures, self-signed certs, and hostname mismatch"
    category = PluginCategory.ssl_tls
    severity = Severity.medium

    ports = SSL_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        sni = host.hostname or None  # SNI so name-based vhosts present the real cert
        for port in host.ports:
            if port.number not in SSL_PORTS or port.state != "open":
                continue
            der = await self._get_cert(host.ip, port.number, sni)
            if not der:
                continue
            findings.extend(self._analyze_cert(der, host.hostname, port.number))
        return findings

    async def _get_cert(self, ip: str, port: int, sni: str | None) -> bytes | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_cert_sync, ip, port, sni)

    def _get_cert_sync(self, ip: str, port: int, sni: str | None) -> bytes | None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with ctx.wrap_socket(
                socket.create_connection((ip, port), timeout=6),
                server_hostname=sni or ip,
            ) as ssock:
                return ssock.getpeercert(binary_form=True)  # DER — populated even without verification
        except Exception as exc:  # noqa: BLE001
            logger.debug("Cert fetch failed %s:%d: %s", ip, port, exc)
            return None

    def _analyze_cert(self, der: bytes, hostname: str | None, port: int) -> list[FindingData]:
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID, NameOID
        except ImportError:
            return []
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Cert parse failed on port %d: %s", port, exc)
            return []

        findings: list[FindingData] = []
        now = datetime.now(tz=timezone.utc)

        # Expiry
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:  # cryptography < 42
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - now).days
        if days_left < 0:
            findings.append(self._f(
                Severity.critical, f"SSL Certificate Expired ({abs(days_left)} days ago)",
                f"The certificate on port {port} expired on {not_after:%Y-%m-%d}.",
                f"notAfter={not_after:%Y-%m-%d}", "Renew the certificate immediately.", port,
            ))
        elif days_left < 30:
            findings.append(self._f(
                Severity.high, f"SSL Certificate Expiring Soon ({days_left} days)",
                f"The certificate on port {port} expires on {not_after:%Y-%m-%d}.",
                f"notAfter={not_after:%Y-%m-%d}", "Renew the certificate before it expires.", port,
            ))

        # Weak signature algorithm
        sig = getattr(cert.signature_hash_algorithm, "name", "") or ""
        if sig.lower() in ("md5", "sha1", "md2"):
            findings.append(self._f(
                Severity.high, "Weak Certificate Signature Algorithm",
                f"The certificate is signed with {sig.upper()}, which is cryptographically broken.",
                f"signatureAlgorithm={sig}", "Reissue the certificate signed with SHA-256 or stronger.", port,
                references=["https://cwe.mitre.org/data/definitions/327.html"],
            ))

        # Self-signed (issuer == subject)
        if cert.issuer == cert.subject:
            findings.append(self._f(
                Severity.medium, "Self-Signed SSL Certificate",
                f"The certificate on port {port} is self-signed (issuer equals subject), so clients "
                "cannot verify the server's identity and are vulnerable to MITM.",
                f"subject={cert.subject.rfc4514_string()}",
                "Install a certificate issued by a trusted CA.", port,
            ))

        # Hostname mismatch (only meaningful when we scanned a real hostname)
        if hostname:
            names: set[str] = set()
            try:
                san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                names.update(san.value.get_values_for_type(x509.DNSName))
            except x509.ExtensionNotFound:
                pass
            names.update(a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
            if names and not _host_matches(hostname, names):
                findings.append(self._f(
                    Severity.medium, "SSL Certificate Hostname Mismatch",
                    f"The certificate presented on port {port} does not cover '{hostname}'. "
                    "Browsers will warn, and the mismatch can mask MITM.",
                    f"host={hostname}; cert names={', '.join(sorted(names))[:300]}",
                    "Issue a certificate whose SAN includes this hostname.", port,
                ))

        return findings

    def _f(self, severity, title, desc, evidence, remediation, port, references=None):
        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=title,
            description=desc,
            evidence=evidence,
            remediation=remediation,
            references=references or [],
            port_number=port,
            protocol="tcp",
        )
