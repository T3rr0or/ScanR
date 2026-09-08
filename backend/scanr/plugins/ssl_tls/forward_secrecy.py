"""Static RSA key exchange — missing forward secrecy.

With RSA key exchange the client encrypts the premaster secret to the server's
public key, so anyone holding the private key can decrypt every session ever
recorded under that certificate. An attacker who captures traffic today and
obtains the key later — breach, seizure, or a stolen backup — reads all of it
retroactively. Ephemeral (EC)DHE suites derive a per-session secret instead, and
the private key alone does not recover it.

Static RSA is also the precondition for the Bleichenbacher family: ROBOT
(2017) and DROWN both require the server to perform RSA decryption during the
handshake. This reports the exposure rather than running an oracle against it,
which keeps the check safe to run anywhere.
"""
from __future__ import annotations

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


class ForwardSecrecyPlugin(PluginBase):
    id = "ssl_tls.forward_secrecy"
    name = "Missing Forward Secrecy (Static RSA Key Exchange)"
    description = (
        "Detect servers accepting RSA key exchange, which exposes recorded "
        "sessions to later key compromise and enables Bleichenbacher attacks"
    )
    category = PluginCategory.ssl_tls
    severity = Severity.medium
    ports = SSL_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        hostname = getattr(host, "hostname", None) or ""
        for port in host.ports:
            if not is_tls_port(port):
                continue
            try:
                accepted = await probe_cipher_suites(
                    host.ip,
                    port.number,
                    SUITE_GROUPS["static RSA key exchange"],
                    hostname=hostname,
                )
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("forward_secrecy: %s:%s failed: %s", host.ip, port.number, exc)
                continue
            if accepted is None:
                continue
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.medium,
                title="TLS Key Exchange Without Forward Secrecy",
                description=(
                    f"The server accepted {accepted.name}, which uses static RSA key "
                    "exchange. The session key is encrypted to the server's certificate "
                    "rather than derived ephemerally, so anyone who obtains the private "
                    "key can decrypt previously recorded traffic. It is also the "
                    "precondition for the ROBOT and DROWN Bleichenbacher attacks, which "
                    "require the server to perform RSA decryption during the handshake."
                ),
                evidence=(
                    f"Offered only static-RSA suites; server selected {accepted.name} "
                    f"(0x{accepted.code:04x})"
                ),
                remediation=(
                    "Disable RSA key exchange and serve only ephemeral suites "
                    "(ECDHE or DHE). On OpenSSL-based servers, restricting the cipher "
                    "list to 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM' removes static "
                    "RSA while keeping broad client compatibility. TLS 1.3 has no "
                    "static-RSA suites at all."
                ),
                references=[
                    "https://robotattack.org/",
                    "https://drownattack.com/",
                    "https://datatracker.ietf.org/doc/html/rfc9325#section-4.1",
                ],
                port_number=port.number,
                protocol="tcp",
            ))
        return findings
