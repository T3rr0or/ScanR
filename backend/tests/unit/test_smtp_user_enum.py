"""SMTP VRFY/EXPN user enumeration detection.

The trap here is 252: Postfix's default answer to VRFY is "252 2.0.0 <addr>",
which it returns for every address whether or not it exists. Reporting on "the
verb was not rejected" would flag most MTAs on the internet, so these pin that
only a reply which actually resolves the account (250/251) counts, and that
502/500/550 refusals produce nothing.
"""
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services.smtp_user_enum import (
    SmtpUserEnumPlugin,
    _is_functional,
    _reply_code,
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
    monkeypatch.setattr(SmtpUserEnumPlugin, "_probe", fake)


BANNER = b"220 mail.example.com ESMTP Sendmail 8.15.2; Mon, 1 Jan 2024 00:00:00 GMT\r\n"

VRFY_OK = b"250 2.1.5 Super User <root@mail.example.com>\r\n"
VRFY_FORWARDED = b"251 2.1.5 User not local; will forward to <root@corp.example.com>\r\n"
VRFY_STUBBED = b"252 2.0.0 root\r\n"
VRFY_NOT_IMPLEMENTED = b"502 5.5.1 VRFY command is disabled\r\n"
VRFY_UNKNOWN_USER = b"550 5.1.1 <root>: Recipient address rejected: User unknown\r\n"

EXPN_OK = b"250-2.1.5 Alice <alice@example.com>\r\n250 2.1.5 Bob <bob@example.com>\r\n"
EXPN_DISABLED = b"502 5.5.1 EXPN command is disabled\r\n"


# ── reply parsing ────────────────────────────────────────────────────────────

def test_reply_code_reads_the_final_line_of_a_multiline_reply():
    assert _reply_code(EXPN_OK) == "250"


def test_reply_code_falls_back_to_a_truncated_multiline_reply():
    assert _reply_code(b"250-2.1.5 Alice <alice@example.com>\r\n") == "250"


@pytest.mark.parametrize("raw", [None, b"", b"garbage with no status code\r\n"])
def test_reply_code_of_a_non_reply_is_none(raw):
    assert _reply_code(raw) is None


@pytest.mark.parametrize("raw,expected", [
    (VRFY_OK, True),
    (VRFY_FORWARDED, True),
    (VRFY_STUBBED, False),
    (VRFY_NOT_IMPLEMENTED, False),
    (b"500 5.5.2 Command unrecognized\r\n", False),
    (VRFY_UNKNOWN_USER, False),
    (b"421 4.7.0 Too many connections\r\n", False),
    (None, False),
])
def test_only_a_resolved_account_counts_as_functional(raw, expected):
    assert _is_functional(raw) is expected


# ── plugin behaviour: true positives ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_working_vrfy_is_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(BANNER, VRFY_OK, EXPN_DISABLED))

    findings = await SmtpUserEnumPlugin().check(None, _host([_port(25)]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.medium
    assert finding.title == "SMTP VRFY User Enumeration Enabled"
    assert "VRFY root" in finding.evidence
    assert "Super User" in finding.evidence
    # EXPN was refused, so it must not appear in the evidence or the title.
    assert "EXPN" not in finding.title
    assert finding.port_number == 25
    assert finding.protocol == "tcp"


@pytest.mark.asyncio
async def test_251_forwarding_reply_counts_as_enumeration(monkeypatch):
    """251 names the forwarding target, which is disclosure in its own right."""
    _patch_probe(monkeypatch, result=(BANNER, VRFY_FORWARDED, EXPN_DISABLED))

    findings = await SmtpUserEnumPlugin().check(None, _host([_port(587)]))

    assert len(findings) == 1
    assert "root@corp.example.com" in findings[0].evidence


@pytest.mark.asyncio
async def test_working_expn_is_reported_with_list_expansion_impact(monkeypatch):
    _patch_probe(monkeypatch, result=(BANNER, VRFY_NOT_IMPLEMENTED, EXPN_OK))

    findings = await SmtpUserEnumPlugin().check(None, _host([_port(25)]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "SMTP EXPN User Enumeration Enabled"
    assert "distribution list" in finding.description
    assert "alice@example.com" in finding.evidence


@pytest.mark.asyncio
async def test_both_verbs_are_reported_in_one_finding(monkeypatch):
    _patch_probe(monkeypatch, result=(BANNER, VRFY_OK, EXPN_OK))

    findings = await SmtpUserEnumPlugin().check(None, _host([_port(25)]))

    assert len(findings) == 1
    assert findings[0].title == "SMTP VRFY and EXPN User Enumeration Enabled"


# ── plugin behaviour: the false-positive traps ───────────────────────────────

@pytest.mark.asyncio
async def test_stubbed_252_reply_is_not_enumeration(monkeypatch):
    """'Cannot VRFY, but will accept and attempt delivery' is the same answer for
    every address, so it confirms nothing about the account."""
    _patch_probe(monkeypatch, result=(BANNER, VRFY_STUBBED, VRFY_STUBBED))

    assert await SmtpUserEnumPlugin().check(None, _host([_port(25)])) == []


@pytest.mark.asyncio
async def test_disabled_verbs_are_not_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(BANNER, VRFY_NOT_IMPLEMENTED, EXPN_DISABLED))

    assert await SmtpUserEnumPlugin().check(None, _host([_port(587)])) == []


@pytest.mark.asyncio
async def test_rejected_probe_is_not_reported(monkeypatch):
    """A bare 550 for one name cannot be told apart from a blanket refusal."""
    _patch_probe(monkeypatch, result=(BANNER, VRFY_UNKNOWN_USER, EXPN_DISABLED))

    assert await SmtpUserEnumPlugin().check(None, _host([_port(25)])) == []


# ── plugin behaviour: nothing to talk to ─────────────────────────────────────

@pytest.mark.asyncio
async def test_non_smtp_service_on_the_port_is_not_reported(monkeypatch):
    _patch_probe(monkeypatch, result=(b"SSH-2.0-OpenSSH_9.6\r\n", VRFY_OK, EXPN_OK))

    assert await SmtpUserEnumPlugin().check(None, _host([_port(25)])) == []


@pytest.mark.asyncio
async def test_closed_port_is_skipped_without_probing(monkeypatch):
    async def fail_if_called(self, ip, port):
        raise AssertionError("must not probe a closed port")
    monkeypatch.setattr(SmtpUserEnumPlugin, "_probe", fail_if_called)

    assert await SmtpUserEnumPlugin().check(None, _host([_port(25, state="closed")])) == []


@pytest.mark.asyncio
async def test_unreachable_port_produces_no_finding_and_no_exception(monkeypatch):
    _patch_probe(monkeypatch, exc=ConnectionRefusedError("refused"))

    assert await SmtpUserEnumPlugin().check(None, _host([_port(25)])) == []


@pytest.mark.asyncio
async def test_silent_port_produces_no_finding(monkeypatch):
    _patch_probe(monkeypatch, result=None)

    assert await SmtpUserEnumPlugin().check(None, _host([_port(587)])) == []


def test_plugin_probes_a_single_well_known_name():
    """One probe per verb — this proves the capability, it does not enumerate."""
    from scanr.plugins.services.smtp_user_enum import PROBE_NAME

    assert PROBE_NAME == "root"
    assert SmtpUserEnumPlugin.intrusive is False
    assert SmtpUserEnumPlugin.destructive is False
