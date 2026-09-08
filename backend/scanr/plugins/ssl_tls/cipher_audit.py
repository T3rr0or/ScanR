"""Weak cipher suite detection.

This check used to open one ordinary TLS connection and inspect the cipher the
handshake settled on. That could never work: the negotiated suite is one both
sides agreed to, and OpenSSL 3.x — which the scanner links against — has RC4,
DES, 3DES and the EXPORT grades compiled out. The client could not offer them,
so the server could not select them, so the check could not fire. It reported
nothing on every target, including genuinely weak ones.

Each family is now probed directly with a hand-built ClientHello that offers
only that family (see `_tls_probe`). A ServerHello naming one of those suites is
positive proof the server accepts it.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.ssl_tls._ports import is_tls_port
from scanr.plugins.ssl_tls._tls_probe import SUITE_GROUPS, probe_cipher_suites

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

SSL_PORTS = [443, 8443, 993, 995, 465, 636, 5986]

# family -> (severity, what an attacker gets, references)
_FAMILIES: dict[str, tuple[Severity, str, list[str]]] = {
    "NULL encryption": (
        Severity.critical,
        "Traffic is authenticated but not encrypted — anyone on the path reads it "
        "in cleartext.",
        ["https://ciphersuite.info/cs/?security=insecure"],
    ),
    "anonymous key exchange": (
        Severity.critical,
        "The server is not authenticated during the handshake, so an active "
        "attacker can machine-in-the-middle the connection without a certificate.",
        ["https://ciphersuite.info/cs/?security=insecure"],
    ),
    "EXPORT grade": (
        Severity.critical,
        "Deliberately weakened 1990s-era key sizes that are breakable on commodity "
        "hardware. Also the precondition for the FREAK and Logjam downgrade attacks.",
        [
            "https://www.smacktls.com/#freak",
            "https://weakdh.org/",
        ],
    ),
    "single DES": (
        Severity.high,
        "A 56-bit key, brute-forceable in hours.",
        ["https://ciphersuite.info/cs/?security=insecure"],
    ),
    "RC4": (
        Severity.high,
        "RC4's keystream biases allow plaintext recovery from repeated "
        "transmissions; prohibited for TLS by RFC 7465.",
        ["https://datatracker.ietf.org/doc/html/rfc7465"],
    ),
    "64-bit block cipher (3DES)": (
        Severity.medium,
        "64-bit blocks make a birthday collision practical on long-lived "
        "connections, recovering plaintext — the Sweet32 attack.",
        ["https://sweet32.info/", "https://nvd.nist.gov/vuln/detail/CVE-2016-2183"],
    ),
}

_SEVERITY_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]


class CipherAuditPlugin(PluginBase):
    id = "ssl_tls.cipher_audit"
    name = "Weak Cipher Suite Detection"
    description = (
        "Probe for NULL, anonymous, EXPORT, DES, RC4 and 64-bit block (Sweet32) "
        "cipher suites with targeted ClientHellos"
    )
    category = PluginCategory.ssl_tls
    severity = Severity.high
    ports = SSL_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        hostname = getattr(host, "hostname", None) or ""
        for port in host.ports:
            if not is_tls_port(port):
                continue
            accepted = await self._probe_families(host.ip, port.number, hostname)
            if accepted:
                findings.append(self._build_finding(accepted, port.number))
        return findings

    async def _probe_families(
        self, ip: str, port: int, hostname: str
    ) -> dict[str, str]:
        """Return {family: accepted suite name} for every weak family offered."""
        families = list(_FAMILIES)
        results = await asyncio.gather(
            *(
                probe_cipher_suites(ip, port, SUITE_GROUPS[family], hostname=hostname)
                for family in families
            ),
            return_exceptions=True,
        )
        accepted: dict[str, str] = {}
        for family, result in zip(families, results):
            if isinstance(result, BaseException):
                logger.debug("cipher_audit: %s probe failed on %s:%s", family, ip, port)
                continue
            if result is not None:
                accepted[family] = result.name
        return accepted

    def _build_finding(self, accepted: dict[str, str], port: int) -> FindingData:
        severity = next(
            sev for sev in _SEVERITY_ORDER
            if any(_FAMILIES[f][0] is sev for f in accepted)
        )
        lines = []
        references: list[str] = []
        for family, suite in accepted.items():
            fam_sev, impact, refs = _FAMILIES[family]
            lines.append(f"- {family} [{fam_sev.value}]: accepted {suite}. {impact}")
            references.extend(refs)

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=f"Weak TLS Cipher Suites Accepted ({len(accepted)} famil"
                  f"{'y' if len(accepted) == 1 else 'ies'})",
            description=(
                "The server completed a handshake using cipher suites that are no "
                "longer considered safe. Each family below was offered on its own, so "
                "the server selecting one is direct proof it accepts it — not merely "
                "that it lists it as a fallback.\n\n" + "\n".join(lines)
            ),
            evidence="\n".join(f"{family} -> {suite}" for family, suite in accepted.items()),
            remediation=(
                "Restrict the server to AEAD suites over TLS 1.2 and 1.3 "
                "(AES-GCM, ChaCha20-Poly1305) with forward secrecy, and disable the "
                "families listed above. On OpenSSL-based servers a starting point is "
                "'ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!RC4'."
            ),
            references=list(dict.fromkeys(references)),
            port_number=port,
            protocol="tcp",
        )
