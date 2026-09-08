"""Cleartext mail authentication detection (POP3, IMAP, SMTP submission).

A mailbox password is rarely mailbox-only: it is usually the directory account
behind SSO, VPN and file shares. So the question worth answering is not "is this
port encrypted" but "would a legitimate client have to put its password on the
wire in the clear to use this service". That is only true when the server both
offers a plaintext login mechanism *and* offers no way to encrypt first.

Two cases therefore look insecure but are not, and this check must not report
them:

  * STARTTLS/STLS advertised — the client can upgrade before authenticating, so
    the credential never crosses the wire in the clear. Poor enforcement is a
    configuration question this probe cannot answer from the outside.
  * IMAP ``LOGINDISABLED`` — the server is explicitly refusing the plaintext
    LOGIN command until the connection is encrypted. That is the hardened state.

Only the plaintext ports are probed. 995/993/465 wrap the same protocols in TLS
from the first byte, so there is nothing to report there.

Every command sent here is a capability query (``CAPA``, ``CAPABILITY``,
``EHLO``) followed by a clean logout. No credentials are ever sent.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING, NamedTuple

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

MAIL_PORTS = [110, 143, 25, 587]
_PROTOCOL_BY_PORT = {110: "pop3", 143: "imap", 25: "smtp", 587: "smtp"}

# Greeting prefixes. A service that does not answer with its protocol's greeting
# is not reported at all — this is what keeps something else parked on 25/110
# out of the results.
_GREETINGS = {
    "pop3": ("+OK",),
    "imap": ("* OK", "* PREAUTH"),
    "smtp": ("220",),
}

_COMMANDS = {
    "pop3": b"CAPA\r\n",
    "imap": b"a1 CAPABILITY\r\n",
    "smtp": b"EHLO scanr.local\r\n",
}

_LOGOUT = {"pop3": b"QUIT\r\n", "imap": b"a2 LOGOUT\r\n", "smtp": b"QUIT\r\n"}

_LABELS = {"pop3": "POP3", "imap": "IMAP", "smtp": "SMTP"}

# SASL mechanisms that transmit the password recoverably. CRAM-MD5 and friends
# are weak but do not hand over the plaintext credential, so they are excluded.
_PLAINTEXT_SASL = ("PLAIN", "LOGIN")

# A 3-digit code followed by a space (not '-') is the last line of an SMTP reply.
_SMTP_FINAL_LINE = re.compile(r"^\d{3} ")
_SMTP_CODE_PREFIX = re.compile(r"^\d{3}[- ]")

REFERENCES = [
    "https://datatracker.ietf.org/doc/html/rfc8314",
    "https://datatracker.ietf.org/doc/html/rfc3207",
    "https://datatracker.ietf.org/doc/html/rfc2595",
    "https://cwe.mitre.org/data/definitions/319.html",
    "https://attack.mitre.org/techniques/T1040/",
]


class _Capabilities(NamedTuple):
    """What the server said about how a client is expected to authenticate."""

    starttls: bool
    # Human-readable names of mechanisms usable *before* any encryption.
    plaintext_auth: list[str]
    # IMAP only: the server refuses plaintext LOGIN until the link is encrypted.
    login_disabled: bool
    # Capability lines worth quoting back as evidence.
    quoted: list[str]


def _lines(raw: bytes | None) -> list[str]:
    if not raw:
        return []
    text = raw.decode("utf-8", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip()]


def _greeting_matches(protocol: str, banner: bytes | None) -> bool:
    lines = _lines(banner)
    if not lines:
        return False
    first = lines[0].upper()
    return any(first.startswith(prefix.upper()) for prefix in _GREETINGS[protocol])


def _dedupe(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)


def _pop3_capabilities(caps: bytes | None) -> _Capabilities:
    lines = _lines(caps)
    # A '-ERR' reply means the server predates RFC 2449. It still has to accept
    # USER/PASS (RFC 1939 mandates it) and it has advertised no STLS, so the
    # password does cross the wire in the clear.
    capa_supported = bool(lines) and lines[0].upper().startswith("+OK")

    starttls = False
    mechs: list[str] = []
    quoted: list[str] = []
    for line in lines:
        if line == "." or line.upper().startswith(("+OK", "-ERR")):
            continue
        parts = line.split()
        name = parts[0].upper()
        if name == "STLS":
            starttls = True
            quoted.append(line)
        elif name == "USER":
            mechs.append("USER/PASS")
            quoted.append(line)
        elif name == "SASL":
            found = [arg.upper() for arg in parts[1:] if arg.upper() in _PLAINTEXT_SASL]
            if found:
                mechs.extend(f"SASL {mech}" for mech in found)
                quoted.append(line)

    if not capa_supported:
        mechs.append("USER/PASS (server does not implement CAPA)")
    return _Capabilities(starttls, _dedupe(mechs), False, quoted)


def _imap_capabilities(caps: bytes | None) -> _Capabilities:
    tokens: set[str] = set()
    quoted: list[str] = []
    for line in _lines(caps):
        upper = line.upper()
        if "CAPABILITY" not in upper:
            continue
        quoted.append(line)
        # The greeting form wraps the list in brackets: * OK [CAPABILITY ...].
        tokens.update(upper.replace("[", " ").replace("]", " ").split())

    if not tokens:
        return _Capabilities(False, [], False, quoted)

    starttls = "STARTTLS" in tokens
    login_disabled = "LOGINDISABLED" in tokens
    if login_disabled:
        return _Capabilities(starttls, [], True, quoted)

    # IMAP4rev1's LOGIN command is always available unless LOGINDISABLED says
    # otherwise, so it does not appear in the capability list.
    mechs = ["LOGIN"]
    mechs.extend(f"AUTH={mech}" for mech in _PLAINTEXT_SASL if f"AUTH={mech}" in tokens)
    return _Capabilities(starttls, _dedupe(mechs), False, quoted)


def _smtp_capabilities(caps: bytes | None) -> _Capabilities:
    starttls = False
    mechs: list[str] = []
    quoted: list[str] = []
    for line in _lines(caps):
        body = _SMTP_CODE_PREFIX.sub("", line)
        parts = body.split()
        if not parts:
            continue
        name = parts[0].upper()
        if name == "STARTTLS":
            starttls = True
            quoted.append(line)
        elif name == "AUTH" or name.startswith("AUTH="):
            # Both the RFC 4954 form ("AUTH PLAIN LOGIN") and the legacy
            # Exchange/Outlook form ("AUTH=PLAIN LOGIN") appear in the wild.
            args = body.replace("=", " ").split()[1:]
            found = [arg.upper() for arg in args if arg.upper() in _PLAINTEXT_SASL]
            if found:
                mechs.extend(f"AUTH {mech}" for mech in found)
                quoted.append(line)
    return _Capabilities(starttls, _dedupe(mechs), False, quoted)


def _capabilities_for(protocol: str, banner: bytes | None, caps: bytes | None) -> _Capabilities:
    if protocol == "pop3":
        return _pop3_capabilities(caps)
    if protocol == "imap":
        # Servers may advertise STARTTLS/LOGINDISABLED in the greeting only.
        # Reading both can only ever suppress a finding, never invent one.
        joined = (banner or b"") + b"\r\n" + (caps or b"")
        return _imap_capabilities(joined)
    return _smtp_capabilities(caps)


def _response_complete(protocol: str, buf: bytes) -> bool:
    lines = _lines(buf)
    if not lines:
        return False
    if protocol == "smtp":
        return any(_SMTP_FINAL_LINE.match(line) for line in lines)
    if protocol == "pop3":
        if lines[0].upper().startswith("-ERR"):
            return True
        return "." in lines
    return any(line.upper().startswith(("A1 OK", "A1 NO", "A1 BAD")) for line in lines)


class MailCleartextPlugin(PluginBase):
    id = "services.mail_cleartext"
    name = "Cleartext Mail Authentication"
    description = "Detect POP3/IMAP/SMTP services that accept plaintext logins with no STARTTLS"
    category = PluginCategory.services
    severity = Severity.high
    ports = MAIL_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in _PROTOCOL_BY_PORT or port.state != "open":
                continue
            try:
                probed = await self._probe(host.ip, port.number)
            except Exception:
                logger.debug(
                    "mail_cleartext: probe failed for %s:%d", host.ip, port.number, exc_info=True
                )
                continue
            if probed is None:
                continue
            banner, caps = probed
            finding = self._analyze(host.ip, port.number, banner, caps)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, ip: str, port: int) -> tuple[bytes, bytes] | None:
        """Return (greeting, capability reply), or None if this is not that service."""
        protocol = _PROTOCOL_BY_PORT[port]
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=6.0
            )
            # Greetings are one reply, but SMTP is allowed to send it multiline.
            banner = await self._read(reader, protocol, timeout=6.0)
            if not _greeting_matches(protocol, banner):
                return None

            writer.write(_COMMANDS[protocol])
            await writer.drain()
            caps = await self._read(reader, protocol, timeout=5.0)

            # Log a clean session end rather than an aborted connection.
            try:
                writer.write(_LOGOUT[protocol])
                await writer.drain()
            except Exception:
                pass
            return banner, caps
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _read(self, reader, protocol: str, timeout: float) -> bytes:
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
            if _response_complete(protocol, buf):
                break
        return buf

    def _analyze(
        self, ip: str, port: int, banner: bytes | None, caps: bytes | None
    ) -> FindingData | None:
        protocol = _PROTOCOL_BY_PORT.get(port)
        if protocol is None or not _greeting_matches(protocol, banner):
            return None

        view = _capabilities_for(protocol, banner, caps)
        if view.starttls or view.login_disabled or not view.plaintext_auth:
            # STARTTLS offered, plaintext login refused, or no login mechanism
            # advertised at all (a plain relay on 25) — no credential is forced
            # onto the wire, so there is nothing to report.
            return None

        label = _LABELS[protocol]
        greeting = _lines(banner)[0] if _lines(banner) else ""
        mechs = ", ".join(view.plaintext_auth)
        starttls_name = "STLS" if protocol == "pop3" else "STARTTLS"

        evidence_parts = [
            f"{ip}:{port} greeting: {greeting}",
            f"offers plaintext authentication ({mechs})",
            f"no {starttls_name} advertised in the {_COMMANDS[protocol].decode().strip()} reply",
        ]
        if view.quoted:
            evidence_parts.append("capability lines: " + " | ".join(view.quoted[:6]))
        evidence = "; ".join(evidence_parts)

        description = (
            f"The {label} service on port {port} advertises plaintext authentication "
            f"({mechs}) and does not advertise {starttls_name}, so a client has no way to "
            "encrypt the session before logging in. Every username and password used on "
            "this port travels the network in recoverable form, so anyone on-path — a "
            "compromised switch or router, a hostile Wi-Fi network, a VPN concentrator, or "
            "an upstream ISP — can harvest working mailbox credentials passively, with no "
            "interaction with the server and nothing in its logs. "
        )
        if protocol == "smtp":
            description += (
                "With those credentials an attacker can send mail as the user through this "
                "submission service — invoice fraud and internal phishing that passes SPF, "
                "DKIM and DMARC because it really is sent by the domain. "
            )
        else:
            description += (
                "With those credentials an attacker reads the entire mailbox: password-reset "
                "links for every other service the user holds, internal documents, and the "
                "address book used to phish colleagues from a trusted account. "
            )
        description += (
            "Mail passwords are usually the user's directory password, so the same "
            "credential typically also opens VPN, SSO and file shares."
        )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title=f"Cleartext {label} Authentication Offered Without {starttls_name}",
            description=description,
            evidence=evidence,
            remediation=(
                f"Enable {starttls_name} on port {port} with a certificate from a trusted CA, "
                "and then require it: reject authentication attempts on an unencrypted "
                "connection (Dovecot 'disable_plaintext_auth = yes', Postfix "
                "'smtpd_tls_auth_only = yes'). Advertising the upgrade is not enough on its "
                "own — a downgrade attack strips it unless plaintext auth is refused. "
                "Move clients to the implicit-TLS ports of RFC 8314 (993 IMAPS, 995 POP3S, "
                "465 submissions) and retire the plaintext ports. "
                "Treat any credential that has been used on this port as exposed and rotate it."
            ),
            references=REFERENCES,
            port_number=port,
            protocol="tcp",
        )
