"""SMTP VRFY/EXPN user enumeration detection.

VRFY asks an SMTP server whether an address exists; EXPN asks it to expand a
mailing list into its members. Where they work, an attacker turns a guessed name
list into a confirmed list of employee accounts — which is the input to password
spraying, and to phishing that names real internal recipients.

The trap this check has to avoid is that most modern MTAs *accept* the verb and
answer nothing useful. Postfix's default reply is ``252 2.0.0 <addr>`` — "I
cannot verify, but I will accept the mail and try to deliver it" — which is the
same answer for every address, existing or not, and therefore discloses nothing.
Fingerprinting on "VRFY is not rejected" reports every Postfix on the internet.

So the verb is probed once, with a name that exists on essentially every
Unix-derived mail host (``root``), and only a reply that actually resolves the
account (250/251) counts. 252 is the stubbed answer; 502/500 mean the verb is
not implemented; 550/551/553 are refusals.

One probe per verb, and only for ``root``: this check proves the capability
exists, it does not enumerate a user list.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

SMTP_PORTS = [25, 587]

# 'root' is aliased on virtually every Unix mail host, and on the ones where it
# is not, the negative answer is still an honest test of the verb.
PROBE_NAME = "root"
# A name no mailbox can plausibly have. A server that answers this the same way
# it answers PROBE_NAME is an accept-all: it confirms every address, so its
# reply carries no information and is not enumeration.
CONTROL_NAME = "scanr-nx-3f9c1a7e-does-not-exist"

_FINAL_LINE = re.compile(r"^(?P<code>\d{3}) ")
_ANY_LINE = re.compile(r"^(?P<code>\d{3})[- ]")

# Codes that mean the server resolved the address for us. 250 = "the address is
# valid"; 251 = "not local, but I know where it forwards to" — the forwarding
# target is itself disclosure.
_FUNCTIONAL_CODES = {"250", "251"}

REFERENCES = [
    "https://datatracker.ietf.org/doc/html/rfc5321#section-3.5",
    "https://cwe.mitre.org/data/definitions/200.html",
    "https://attack.mitre.org/techniques/T1087/003/",
]


def _reply_code(raw: bytes | None) -> str | None:
    """The status code of an SMTP reply, taken from its last line."""
    if not raw:
        return None
    lines = [line.strip() for line in raw.decode("utf-8", errors="replace").splitlines() if line.strip()]
    for line in reversed(lines):
        match = _FINAL_LINE.match(line)
        if match:
            return match.group("code")
    # A truncated multiline reply still tells us which code was being sent.
    for line in reversed(lines):
        match = _ANY_LINE.match(line)
        if match:
            return match.group("code")
    return None


def _reply_text(raw: bytes | None) -> str:
    if not raw:
        return ""
    return " ".join(
        line.strip() for line in raw.decode("utf-8", errors="replace").splitlines() if line.strip()
    )[:200]


def _is_functional(raw: bytes | None) -> bool:
    """True only when the server actually resolved the probed account."""
    return _reply_code(raw) in _FUNCTIONAL_CODES


class SmtpUserEnumPlugin(PluginBase):
    id = "services.smtp_user_enum"
    name = "SMTP User Enumeration (VRFY/EXPN)"
    description = "Detect SMTP servers where VRFY or EXPN confirms whether an account exists"
    category = PluginCategory.services
    severity = Severity.medium
    ports = SMTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in SMTP_PORTS or port.state != "open":
                continue
            try:
                probed = await self._probe(host.ip, port.number)
            except Exception:
                logger.debug(
                    "smtp_user_enum: probe failed for %s:%d", host.ip, port.number, exc_info=True
                )
                continue
            if probed is None:
                continue
            banner, vrfy, expn, control = probed
            finding = self._analyze(host.ip, port.number, banner, vrfy, expn, control)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, ip: str, port: int) -> tuple[bytes, bytes, bytes, bytes] | None:
        """Return (greeting, VRFY reply, EXPN reply, VRFY control reply).

        The control reply is what separates a server that genuinely resolves
        mailboxes from one that confirms anything it is asked.
        """
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=6.0
            )
            banner = await self._read(reader, timeout=6.0)
            if _reply_code(banner) != "220":
                return None

            writer.write(b"EHLO scanr.local\r\n")
            await writer.drain()
            await self._read(reader, timeout=5.0)

            writer.write(f"VRFY {PROBE_NAME}\r\n".encode())
            await writer.drain()
            vrfy = await self._read(reader, timeout=5.0)

            writer.write(f"EXPN {PROBE_NAME}\r\n".encode())
            await writer.drain()
            expn = await self._read(reader, timeout=5.0)

            writer.write(f"VRFY {CONTROL_NAME}\r\n".encode())
            await writer.drain()
            control = await self._read(reader, timeout=5.0)

            try:
                writer.write(b"QUIT\r\n")
                await writer.drain()
            except Exception:
                pass
            return banner, vrfy, expn, control
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _read(self, reader, timeout: float) -> bytes:
        buf = b""
        while len(buf) < 32768:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
            if any(_FINAL_LINE.match(line.strip()) for line in buf.decode("utf-8", "replace").splitlines()):
                break
        return buf

    def _analyze(
        self,
        ip: str,
        port: int,
        banner: bytes | None,
        vrfy: bytes | None,
        expn: bytes | None,
        control: bytes | None = None,
    ) -> FindingData | None:
        if _reply_code(banner) != "220":
            # Not an SMTP greeting — never report.
            return None

        vrfy_works = _is_functional(vrfy)
        expn_works = _is_functional(expn)
        if not (vrfy_works or expn_works):
            return None

        # Accept-all check. A server that confirms an address which cannot exist
        # confirms everything, so a 250 for a real name proves nothing and an
        # attacker learns no more than they already knew. Only suppress on a
        # reply we actually got: no control reply means the probe did not
        # complete, and we fall back to reporting rather than silently dropping.
        if control is not None and _is_functional(control):
            logger.debug(
                "smtp_user_enum: %s:%s confirms %r too — accept-all, not enumeration",
                ip, port, CONTROL_NAME,
            )
            return None

        verbs = [name for name, works in (("VRFY", vrfy_works), ("EXPN", expn_works)) if works]
        verb_list = " and ".join(verbs)

        evidence_parts = [f"{ip}:{port} greeting: {_reply_text(banner)}"]
        if vrfy_works:
            evidence_parts.append(f"VRFY {PROBE_NAME} -> {_reply_text(vrfy)}")
        if expn_works:
            evidence_parts.append(f"EXPN {PROBE_NAME} -> {_reply_text(expn)}")

        description = (
            f"The SMTP service on port {port} answered {verb_list} with a resolved account "
            f"rather than the non-committal 252 that a hardened server returns. An attacker "
            "can therefore ask this server, one name at a time, which addresses exist — "
            "turning a list of names harvested from LinkedIn or a breach dump into a "
            "confirmed list of live accounts. That list is the input to password spraying "
            "(where a single common password against many valid accounts avoids per-account "
            "lockout) and to phishing that addresses real people in real reporting lines. "
            "The probe here used one well-known name only; nothing prevents an attacker from "
            "running it across a dictionary."
        )
        if expn_works:
            description += (
                " EXPN is the more serious of the two: it expands a distribution list into "
                "its member addresses, so a single query can return an entire department, "
                "and lists such as 'all-staff' or 'security' map out the organisation."
            )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title=f"SMTP {verb_list} User Enumeration Enabled",
            description=description,
            evidence="; ".join(evidence_parts),
            remediation=(
                "Disable both verbs on any internet-facing MTA: Postfix "
                "'disable_vrfy_command = yes', Exim 'acl_smtp_vrfy'/'acl_smtp_expn' set to "
                "deny, Sendmail 'PrivacyOptions' including 'noexpn,novrfy'. "
                "EXPN should be off even internally — mailing-list membership is org-chart "
                "disclosure. "
                "Make sure the same information does not leak through RCPT TO instead: "
                "reject unknown recipients at a consistent, rate-limited stage rather than "
                "with a distinguishable 550 per address."
            ),
            references=REFERENCES,
            port_number=port,
            protocol="tcp",
        )
