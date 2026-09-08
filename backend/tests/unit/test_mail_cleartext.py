"""Cleartext mail authentication detection (POP3/IMAP/SMTP).

The load-bearing part of this check is what it refuses to report. A server that
advertises STARTTLS/STLS lets the client encrypt before authenticating, and an
IMAP server advertising LOGINDISABLED is refusing plaintext logins outright —
both are the hardened state and neither is a finding. These pin that, alongside
the positive case (a plaintext mechanism offered with no upgrade available) and
the fingerprint gate that keeps a non-mail service off the report.
"""
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services.mail_cleartext import (
    MailCleartextPlugin,
    _greeting_matches,
    _imap_capabilities,
    _pop3_capabilities,
    _response_complete,
    _smtp_capabilities,
)


def _port(number, state="open"):
    return SimpleNamespace(number=number, state=state, banner=None, service=None)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


def _patch_probe(monkeypatch, result=None, exc=None):
    async def fake(self, ip, port):
        if exc is not None:
            raise exc
        return result
    monkeypatch.setattr(MailCleartextPlugin, "_probe", fake)


# Canned wire data -------------------------------------------------------------

POP3_BANNER = b"+OK Dovecot (Ubuntu) ready.\r\n"
POP3_CAPA_PLAIN = b"+OK\r\nCAPA\r\nTOP\r\nUIDL\r\nUSER\r\nSASL PLAIN LOGIN\r\n.\r\n"
POP3_CAPA_STLS = b"+OK\r\nCAPA\r\nTOP\r\nUIDL\r\nSTLS\r\nUSER\r\nSASL PLAIN LOGIN\r\n.\r\n"

IMAP_BANNER = b"* OK [CAPABILITY IMAP4rev1 ID ENABLE] Dovecot ready.\r\n"
IMAP_CAPS_PLAIN = (
    b"* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN\r\n"
    b"a1 OK Pre-login capabilities listed, post-login capabilities have more.\r\n"
)
IMAP_CAPS_STARTTLS = (
    b"* CAPABILITY IMAP4rev1 SASL-IR ID ENABLE IDLE STARTTLS LOGINDISABLED\r\n"
    b"a1 OK Capability completed.\r\n"
)
IMAP_CAPS_LOGINDISABLED = (
    b"* CAPABILITY IMAP4rev1 SASL-IR ID ENABLE IDLE LOGINDISABLED AUTH=CRAM-MD5\r\n"
    b"a1 OK Capability completed.\r\n"
)

SMTP_BANNER = b"220 mail.example.com ESMTP Postfix (Debian/GNU)\r\n"
SMTP_EHLO_PLAIN = (
    b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
    b"250-AUTH PLAIN LOGIN\r\n250 HELP\r\n"
)
SMTP_EHLO_STARTTLS = (
    b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
    b"250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n"
)
SMTP_EHLO_RELAY_ONLY = (
    b"250-mx.example.com\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250 8BITMIME\r\n"
)


# ── capability parsing ───────────────────────────────────────────────────────

def test_pop3_user_and_sasl_are_plaintext_mechanisms():
    view = _pop3_capabilities(POP3_CAPA_PLAIN)
    assert view.starttls is False
    assert "USER/PASS" in view.plaintext_auth
    assert "SASL PLAIN" in view.plaintext_auth


def test_pop3_stls_capability_is_recognised():
    assert _pop3_capabilities(POP3_CAPA_STLS).starttls is True


def test_pop3_without_capa_still_forces_user_pass():
    """RFC 1939 mandates USER/PASS, so a server with no CAPA has no upgrade path."""
    view = _pop3_capabilities(b"-ERR Unknown command\r\n")
    assert view.starttls is False
    assert view.plaintext_auth


def test_imap_login_is_implicit_unless_disabled():
    view = _imap_capabilities(IMAP_CAPS_PLAIN)
    assert view.plaintext_auth == ["LOGIN", "AUTH=PLAIN"]
    assert view.login_disabled is False


def test_imap_logindisabled_leaves_no_plaintext_mechanism():
    view = _imap_capabilities(IMAP_CAPS_LOGINDISABLED)
    assert view.login_disabled is True
    assert view.plaintext_auth == []


def test_imap_starttls_is_recognised():
    assert _imap_capabilities(IMAP_CAPS_STARTTLS).starttls is True


def test_smtp_auth_line_yields_plaintext_mechanisms():
    view = _smtp_capabilities(SMTP_EHLO_PLAIN)
    assert view.starttls is False
    assert view.plaintext_auth == ["AUTH PLAIN", "AUTH LOGIN"]


def test_smtp_legacy_auth_equals_form_is_parsed():
    """Exchange and older Outlook clients use the 'AUTH=LOGIN' spelling."""
    view = _smtp_capabilities(b"250-mail\r\n250-AUTH=LOGIN PLAIN\r\n250 HELP\r\n")
    assert view.plaintext_auth == ["AUTH LOGIN", "AUTH PLAIN"]


def test_smtp_relay_offering_no_auth_has_no_plaintext_mechanism():
    view = _smtp_capabilities(SMTP_EHLO_RELAY_ONLY)
    assert view.plaintext_auth == []


def test_smtp_cram_md5_only_is_not_plaintext():
    view = _smtp_capabilities(b"250-mail\r\n250-AUTH CRAM-MD5 DIGEST-MD5\r\n250 HELP\r\n")
    assert view.plaintext_auth == []


# ── greeting fingerprint and read framing ────────────────────────────────────

@pytest.mark.parametrize("protocol,banner,expected", [
    ("pop3", POP3_BANNER, True),
    ("pop3", b"SSH-2.0-OpenSSH_9.6\r\n", False),
    ("imap", IMAP_BANNER, True),
    ("imap", b"* PREAUTH IMAP4rev1 server ready\r\n", True),
    ("imap", b"HTTP/1.1 400 Bad Request\r\n", False),
    ("smtp", SMTP_BANNER, True),
    ("smtp", b"", False),
    ("smtp", None, False),
])
def test_greeting_fingerprint(protocol, banner, expected):
    assert _greeting_matches(protocol, banner) is expected


def test_smtp_reply_is_complete_only_on_the_space_delimited_line():
    assert _response_complete("smtp", b"250-mail.example.com\r\n250-PIPELINING\r\n") is False
    assert _response_complete("smtp", SMTP_EHLO_PLAIN) is True


def test_pop3_reply_is_complete_on_the_dot_or_an_error():
    assert _response_complete("pop3", b"+OK\r\nTOP\r\nUSER\r\n") is False
    assert _response_complete("pop3", POP3_CAPA_PLAIN) is True
    assert _response_complete("pop3", b"-ERR Unknown command\r\n") is True


def test_imap_reply_is_complete_on_the_tagged_line():
    assert _response_complete("imap", b"* CAPABILITY IMAP4rev1\r\n") is False
    assert _response_complete("imap", IMAP_CAPS_PLAIN) is True


# ── plugin behaviour: true positives ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_pop3_plaintext_login_without_stls_is_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(POP3_BANNER, POP3_CAPA_PLAIN))

    findings = await MailCleartextPlugin().check(None, _host([_port(110)]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.title == "Cleartext POP3 Authentication Offered Without STLS"
    assert "USER/PASS" in finding.evidence
    assert "Dovecot" in finding.evidence
    assert finding.port_number == 110
    assert finding.protocol == "tcp"


@pytest.mark.asyncio
async def test_imap_plaintext_login_without_starttls_is_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(IMAP_BANNER, IMAP_CAPS_PLAIN))

    findings = await MailCleartextPlugin().check(None, _host([_port(143)]))

    assert len(findings) == 1
    assert findings[0].title == "Cleartext IMAP Authentication Offered Without STARTTLS"
    assert "AUTH=PLAIN" in findings[0].evidence


@pytest.mark.asyncio
async def test_smtp_submission_plaintext_auth_is_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(SMTP_BANNER, SMTP_EHLO_PLAIN))

    findings = await MailCleartextPlugin().check(None, _host([_port(587)]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Cleartext SMTP Authentication Offered Without STARTTLS"
    assert "AUTH PLAIN" in finding.evidence
    # Stolen submission credentials mean mail sent as the user, which is the
    # concrete impact this finding has to explain.
    assert "send mail as the user" in finding.description
    assert finding.port_number == 587


@pytest.mark.asyncio
async def test_every_affected_port_is_reported_separately(monkeypatch):
    async def fake(self, ip, port):
        return {
            110: (POP3_BANNER, POP3_CAPA_PLAIN),
            143: (IMAP_BANNER, IMAP_CAPS_PLAIN),
        }.get(port)
    monkeypatch.setattr(MailCleartextPlugin, "_probe", fake)

    findings = await MailCleartextPlugin().check(None, _host([_port(110), _port(143)]))

    assert sorted(f.port_number for f in findings) == [110, 143]


# ── plugin behaviour: the false-positive traps ───────────────────────────────

@pytest.mark.asyncio
async def test_pop3_advertising_stls_is_not_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(POP3_BANNER, POP3_CAPA_STLS))
    assert await MailCleartextPlugin().check(None, _host([_port(110)])) == []


@pytest.mark.asyncio
async def test_imap_advertising_starttls_is_not_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(IMAP_BANNER, IMAP_CAPS_STARTTLS))
    assert await MailCleartextPlugin().check(None, _host([_port(143)])) == []


@pytest.mark.asyncio
async def test_imap_logindisabled_is_not_reported(monkeypatch):
    """LOGINDISABLED means the server refuses plaintext LOGIN — the hardened state."""
    _patch_probe(monkeypatch, result=(IMAP_BANNER, IMAP_CAPS_LOGINDISABLED))
    assert await MailCleartextPlugin().check(None, _host([_port(143)])) == []


@pytest.mark.asyncio
async def test_smtp_advertising_starttls_is_not_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(SMTP_BANNER, SMTP_EHLO_STARTTLS))
    assert await MailCleartextPlugin().check(None, _host([_port(587)])) == []


@pytest.mark.asyncio
async def test_mta_offering_no_auth_at_all_is_not_reported(monkeypatch):
    """Port 25 between MTAs carries no credentials, so there is nothing to steal."""
    _patch_probe(monkeypatch, result=(SMTP_BANNER, SMTP_EHLO_RELAY_ONLY))
    assert await MailCleartextPlugin().check(None, _host([_port(25)])) == []


@pytest.mark.asyncio
async def test_imap_starttls_advertised_only_in_the_greeting_is_honoured(monkeypatch):
    """Reading the greeting as well can only suppress a finding, never invent one."""
    banner = b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] ready.\r\n"
    _patch_probe(monkeypatch, result=(banner, b"a1 BAD Unknown command\r\n"))
    assert await MailCleartextPlugin().check(None, _host([_port(143)])) == []


# ── plugin behaviour: nothing to talk to ─────────────────────────────────────

@pytest.mark.asyncio
async def test_non_mail_service_on_a_mail_port_is_not_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(b"SSH-2.0-OpenSSH_9.6\r\n", b"+OK USER\r\n.\r\n"))
    assert await MailCleartextPlugin().check(None, _host([_port(110)])) == []


@pytest.mark.asyncio
async def test_closed_port_is_skipped_without_probing(monkeypatch):
    async def fail_if_called(self, ip, port):
        raise AssertionError("must not probe a closed port")
    monkeypatch.setattr(MailCleartextPlugin, "_probe", fail_if_called)

    assert await MailCleartextPlugin().check(None, _host([_port(110, state="closed")])) == []


@pytest.mark.asyncio
async def test_unreachable_port_produces_no_finding_and_no_exception(monkeypatch):
    _patch_probe(monkeypatch, exc=TimeoutError("connect timed out"))
    assert await MailCleartextPlugin().check(None, _host([_port(143)])) == []


@pytest.mark.asyncio
async def test_silent_port_produces_no_finding(monkeypatch):
    _patch_probe(monkeypatch, result=None)
    assert await MailCleartextPlugin().check(None, _host([_port(25)])) == []


def test_plugin_sends_no_attack_payloads_and_no_credentials():
    assert MailCleartextPlugin.intrusive is False
    assert MailCleartextPlugin.destructive is False
