"""Ticketbleed memory disclosure (CVE-2016-9244).

F5 BIG-IP's session-ticket implementation copies the client's session ID into a
fixed 32-byte field without zeroing the rest of it. A client that sends a
*short* session ID gets back a full 32 bytes: its own prefix, followed by
whatever happened to be in the appliance's memory. Repeated, that reads out
session data and eventually private key material from a device terminating TLS
for the whole estate.

Detection is a single ClientHello with a one-byte session ID and a session-ticket
extension. A healthy server does one of two things: echoes the short ID exactly
(accepting resumption), or issues its own fresh random 32-byte ID. Only a
vulnerable one returns 32 bytes that *begin with our byte* — because the rest is
uninitialised memory sitting behind our prefix.

Two probes with different marker bytes must both come back prefixed for the
plugin to report. A random 32-byte ID matching one chosen byte is a 1-in-256
coincidence; matching two different ones in sequence is roughly 1 in 65,000, so
the evidence is the server's own behaviour rather than a guess.

The probe reads at most 31 bytes of the appliance's memory into the scan's
evidence and never completes the handshake. It is classified as an exploit-grade
probe because it is a memory disclosure, not a configuration observation.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.ssl_tls._handshake import (
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

# Distinct, non-trivial markers. Different values across the two probes are what
# rules out a server that simply always returns the same 32-byte ID.
MARKERS = (b"\x41", b"\x7e")
# A syntactically plausible but meaningless ticket: the bug is in how the
# appliance sets up the session ID before it ever validates the ticket.
_FAKE_TICKET = bytes(range(32))

_SESSION_ID_FIELD = 32


def leaked_memory(marker: bytes, session_id: bytes) -> bytes | None:
    """The bytes behind our prefix, or None when this reply is not a leak.

    A full-length session ID that starts with the exact byte we chose is the
    signature: the server did not generate it (it would not know our byte) and
    did not echo it (that would be one byte long).
    """
    if len(session_id) != _SESSION_ID_FIELD:
        return None
    if not session_id.startswith(marker):
        return None
    return session_id[len(marker):]


class TicketbleedPlugin(PluginBase):
    id = "ssl_tls.ticketbleed"
    name = "Ticketbleed Memory Disclosure (CVE-2016-9244)"
    description = (
        "Detect F5 BIG-IP session-ticket memory disclosure via a short "
        "session ID in the ClientHello"
    )
    category = PluginCategory.ssl_tls
    severity = Severity.high
    cve_ids = ["CVE-2016-9244"]
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    ports = sorted(COMMON_TLS_PORTS)

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        hostname = (getattr(host, "hostname", None) or "").strip()
        for port in host.ports:
            if not is_tls_port(port):
                continue
            leaks = await self._probe_markers(host.ip, port.number, hostname)
            if leaks is None:
                continue
            findings.append(self._build_finding(host.ip, port.number, leaks))
        return findings

    async def _probe_markers(
        self, ip: str, port: int, hostname: str
    ) -> list[tuple[bytes, bytes]] | None:
        """Leaked tails per marker, or None unless every marker came back prefixed."""
        leaks: list[tuple[bytes, bytes]] = []
        for marker in MARKERS:
            hello = await self._server_hello(ip, port, hostname, marker)
            if hello is None:
                return None
            leak = leaked_memory(marker, hello.session_id)
            if leak is None:
                return None
            leaks.append((marker, leak))
        return leaks

    @staticmethod
    async def _server_hello(
        ip: str, port: int, hostname: str, marker: bytes
    ) -> ServerHello | None:
        client_hello = build_feature_hello(
            hostname,
            compression=(0x00,),
            request_ocsp=False,
            offer_renegotiation_info=False,
            session_id=marker,
            ticket=_FAKE_TICKET,
        )
        raw = await probe_handshake(ip, port, client_hello)
        return parse_first_flight(raw)

    def _build_finding(
        self, ip: str, port: int, leaks: list[tuple[bytes, bytes]]
    ) -> FindingData:
        evidence = [
            f"{ip}:{port} — two ClientHellos sent, each with a 1-byte session ID and "
            "a session_ticket extension.",
        ]
        for marker, leak in leaks:
            evidence.append(
                f"  session_id sent: {marker.hex()} (1 byte) → "
                f"session_id returned: {(marker + leak).hex()} (32 bytes)"
            )
            evidence.append(f"    uninitialised tail ({len(leak)} bytes): {leak.hex()}")
        evidence.append("")
        evidence.append(
            "A server that generated this ID could not have known the marker byte, and "
            "a server echoing our ID would have returned one byte. The 31 bytes behind "
            "the marker are the appliance's own memory."
        )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="Ticketbleed Memory Disclosure (CVE-2016-9244)",
            description=(
                f"The TLS service on {ip}:{port} returns uninitialised memory in the "
                "session ID field of its ServerHello. This is Ticketbleed, an F5 BIG-IP "
                "defect: the appliance copies a short client session ID into a 32-byte "
                "field without clearing the remainder.\n\n"
                "Each handshake leaks up to 31 bytes, and handshakes are unlimited and "
                "unauthenticated, so an attacker simply repeats the request and "
                "reassembles the appliance's memory. What comes back is whatever that "
                "memory held: other users' session data, cookies, request contents, and "
                "in the original research the device's TLS private key. A load balancer "
                "terminating TLS for the estate means one key compromise covers every "
                "service behind it.\n\n"
                "Treat the certificate on this service as compromised until it has been "
                "rotated — the leak may already have exposed it, and patching does not "
                "un-leak a key."
            ),
            evidence="\n".join(evidence),
            remediation=(
                "Patch the BIG-IP to a fixed release (11.6.1 HF2, 12.0.0 HF4, 12.1.2, "
                "or later — see F5 K05121675). As an immediate mitigation, disable "
                "session tickets on the affected Client SSL profile, which closes the "
                "leak without a reboot.\n\n"
                "Then rotate: reissue and revoke the certificate and private key on this "
                "virtual server, and invalidate active sessions. The leaked bytes cannot "
                "be recalled, so anything that was in that memory has to be treated as "
                "known to an attacker."
            ),
            references=[
                "https://filippo.io/Ticketbleed/",
                "https://nvd.nist.gov/vuln/detail/CVE-2016-9244",
                "https://my.f5.com/manage/s/article/K05121675",
            ],
            cve_ids=self.cve_ids,
            cvss_vector=self.cvss_vector,
            cvss_score=7.5,
            port_number=port,
            protocol="tcp",
            peer_review_command=f"https://filippo.io/Ticketbleed/  # or: testssl.sh --ticketbleed {ip}:{port}",
        )
