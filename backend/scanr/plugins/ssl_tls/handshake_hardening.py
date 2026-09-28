"""TLS handshake protections: secure renegotiation, compression, OCSP stapling.

The existing TLS plugins cover which protocol versions and cipher suites a server
accepts. This one covers the handshake features around them — three settings that
are invisible to a version/cipher audit but each change what an attacker can do:

* **Secure renegotiation (RFC 5746).** Without it, an attacker can prepend their
  own plaintext to a client's request and have the server treat both as one
  authenticated stream (CVE-2009-3555).
* **Record compression.** Compressing before encrypting leaks plaintext length,
  which recovers session cookies byte by byte (CRIME, CVE-2012-4929).
* **OCSP stapling.** Without it, revocation checking depends on the client
  reaching the CA — which most clients silently skip, so a revoked certificate
  keeps working.

Read-only: one ClientHello, one server flight, connection closed. No
renegotiation is ever requested, no application data is sent, and nothing is
decrypted.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.ssl_tls._handshake import (
    COMPRESSION_NULL,
    EXT_RENEGOTIATION_INFO,
    ServerHello,
    build_feature_hello,
    parse_first_flight,
    probe_handshake,
)
from scanr.plugins.ssl_tls._ports import COMMON_TLS_PORTS, is_tls_port

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_COMPRESSION_NAMES = {0x01: "DEFLATE", 0x40: "LZS"}


def insecure_renegotiation(hello: ServerHello) -> bool:
    """True when the server did not acknowledge RFC 5746.

    TLS 1.3 removed renegotiation entirely, so a TLS 1.3 server that omits the
    extension is not vulnerable — it simply has nothing to renegotiate.
    """
    if hello.is_tls13:
        return False
    return not hello.has_extension(EXT_RENEGOTIATION_INFO)


def compression_enabled(hello: ServerHello) -> bool:
    return hello.compression != COMPRESSION_NULL


class HandshakeHardeningPlugin(PluginBase):
    id = "ssl_tls.handshake_hardening"
    name = "TLS Handshake Hardening"
    description = (
        "Check secure renegotiation (RFC 5746), TLS record compression (CRIME) "
        "and OCSP stapling from the server's handshake"
    )
    category = PluginCategory.ssl_tls
    severity = Severity.medium
    ports = sorted(COMMON_TLS_PORTS)

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        hostname = (getattr(host, "hostname", None) or "").strip()
        for port in host.ports:
            if not is_tls_port(port):
                continue
            hello = await self._server_hello(host.ip, port.number, hostname)
            if hello is None:
                continue
            findings.extend(self._assess(host.ip, port.number, hello))
        return findings

    @staticmethod
    async def _server_hello(ip: str, port: int, hostname: str) -> ServerHello | None:
        client_hello = build_feature_hello(hostname)
        raw = await probe_handshake(ip, port, client_hello)
        return parse_first_flight(raw)

    def _assess(self, ip: str, port: int, hello: ServerHello) -> list[FindingData]:
        findings: list[FindingData] = []
        context_line = (
            f"{ip}:{port} negotiated {hello.version_name()} with cipher "
            f"0x{hello.cipher:04x}"
        )

        if insecure_renegotiation(hello):
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.medium,
                title="TLS Secure Renegotiation Not Supported (RFC 5746)",
                description=(
                    f"The TLS service on {ip}:{port} did not return the "
                    "renegotiation_info extension, so it does not implement RFC 5746 "
                    "secure renegotiation.\n\n"
                    "An attacker who can intercept the connection opens their own TLS "
                    "session to the server, sends a request of their choosing, then "
                    "renegotiates and splices the victim's handshake onto the same "
                    "connection. The server treats the attacker's prefix and the "
                    "victim's authenticated request as one stream — so the attacker's "
                    "request executes with the victim's credentials. The victim sees "
                    "nothing unusual."
                ),
                evidence=(
                    f"{context_line}\n"
                    "ClientHello offered the renegotiation_info extension (0xff01) with "
                    "an empty renegotiated_connection field.\n"
                    "ServerHello extensions returned: "
                    + (", ".join(f"0x{ext:04x}" for ext in sorted(hello.extensions)) or "(none)")
                    + "\nrenegotiation_info (0xff01): absent"
                ),
                remediation=(
                    "Upgrade the TLS stack — every maintained OpenSSL, LibreSSL, "
                    "GnuTLS, NSS and Schannel build has supported RFC 5746 for over a "
                    "decade, so its absence usually means an end-of-life library or "
                    "appliance firmware. Where renegotiation is not needed at all, "
                    "disable it outright (nginx: it is off by default; Apache: "
                    "'SSLInsecureRenegotiation off'), and prefer TLS 1.3, which removes "
                    "renegotiation from the protocol."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc5746",
                    "https://nvd.nist.gov/vuln/detail/CVE-2009-3555",
                ],
                cve_ids=["CVE-2009-3555"],
                port_number=port,
                protocol="tcp",
                peer_review_command=f"openssl s_client -connect {ip}:{port} </dev/null 2>&1 | grep -i renegotiation",
            ))

        if compression_enabled(hello):
            method = _COMPRESSION_NAMES.get(hello.compression, f"0x{hello.compression:02x}")
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.medium,
                title="TLS Record Compression Enabled (CRIME)",
                description=(
                    f"The TLS service on {ip}:{port} selected the {method} compression "
                    "method. Compressing data before encrypting it makes the ciphertext "
                    "length depend on the plaintext's content.\n\n"
                    "An attacker who can make the victim's browser issue requests to "
                    "this server — any page on any site can do that — guesses a secret "
                    "byte at a time and watches the compressed length. A correct guess "
                    "compresses better. That recovers session cookies and "
                    "Authorization headers from an otherwise sound TLS connection "
                    "(CRIME, CVE-2012-4929)."
                ),
                evidence=(
                    f"{context_line}\n"
                    "ClientHello offered compression methods: null, DEFLATE\n"
                    f"ServerHello selected compression method: 0x{hello.compression:02x} ({method})"
                ),
                remediation=(
                    "Disable TLS compression. OpenSSL: build with OPENSSL_NO_COMP or "
                    "set 'SSL_OP_NO_COMPRESSION' (nginx and Apache disable it by "
                    "default on modern OpenSSL). Where the stack cannot be changed, "
                    "moving to TLS 1.3 removes record compression from the protocol."
                ),
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2012-4929",
                    "https://en.wikipedia.org/wiki/CRIME",
                ],
                cve_ids=["CVE-2012-4929"],
                port_number=port,
                protocol="tcp",
                peer_review_command=f"openssl s_client -connect {ip}:{port} </dev/null 2>&1 | grep -i compression",
            ))

        if not hello.stapled_ocsp() and not hello.is_tls13:
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.low,
                title="OCSP Stapling Not Enabled",
                description=(
                    f"The TLS service on {ip}:{port} did not staple a revocation "
                    "response, although the handshake asked for one.\n\n"
                    "Without stapling, a client that wants to know whether this "
                    "certificate has been revoked must contact the CA itself. Most "
                    "browsers treat a failed or slow OCSP lookup as success ('soft "
                    "fail'), so in practice revocation is not checked at all: a "
                    "certificate revoked after a key compromise keeps working against "
                    "this service."
                ),
                evidence=(
                    f"{context_line}\n"
                    "ClientHello included status_request (extension 0x0005, OCSP).\n"
                    "Server returned neither a status_request acknowledgement nor a "
                    "CertificateStatus message."
                ),
                remediation=(
                    "Enable OCSP stapling: nginx 'ssl_stapling on; ssl_stapling_verify "
                    "on;' with a resolver configured, Apache 'SSLUseStapling on' plus "
                    "'SSLStaplingCache'. The server needs outbound access to the CA's "
                    "OCSP responder. Certificates issued with the 'must-staple' "
                    "extension make the protection enforceable rather than advisory."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc6961",
                    "https://en.wikipedia.org/wiki/OCSP_stapling",
                ],
                port_number=port,
                protocol="tcp",
                peer_review_command=f"openssl s_client -connect {ip}:{port} -status </dev/null 2>&1 | grep -A2 'OCSP response'",
            ))

        return findings
