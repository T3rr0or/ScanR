"""SMTP smuggling (non-standard end-of-data) detection.

Pins the reply parsing, the server-domain selection for the harmless probe
recipient, and the probe body that ends only with the non-standard terminator.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.services.smtp_smuggling import (
    EOD_SEQUENCES,
    SmtpSmugglingPlugin,
    build_probe_body,
    is_positive,
    reply_code,
    server_domain,
)


def _port(number=25, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.120", hostname="mail.example"):
    return SimpleNamespace(ip=ip, hostname=hostname, ports=ports)


def test_reply_code_and_positive():
    assert reply_code(b"220 mail ESMTP\r\n") == 220
    assert reply_code(b"250-a\r\n250 OK\r\n") == 250
    assert is_positive(250) and not is_positive(550) and not is_positive(None)


def test_server_domain_prefers_the_banner():
    assert server_domain("220 mail.corp.example.com ESMTP", "1.2.3.4") == "mail.corp.example.com"
    assert server_domain("220 ESMTP ready", "target.example") == "target.example"
    assert server_domain("220 192.0.2.1 ESMTP", "target.example") == "target.example"


def test_probe_body_ends_only_with_the_nonstandard_terminator():
    body = build_probe_body("x@y.z", EOD_SEQUENCES[0])
    assert body.endswith(b"\n.\n")
    assert b"\r\n.\r\n" not in body     # the standard terminator is never sent


@pytest.mark.asyncio
async def test_accepted_sequence_is_reported(monkeypatch):
    async def fake_test(self, host, port):
        return EOD_SEQUENCES[0], "220 mail.example ESMTP", "probe@mail.example"
    monkeypatch.setattr(SmtpSmugglingPlugin, "_test_sequences", fake_test)
    findings = await SmtpSmugglingPlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].cve_ids == ["CVE-2023-51764", "CVE-2023-51765", "CVE-2023-51766"]


@pytest.mark.asyncio
async def test_conforming_server_is_silent(monkeypatch):
    async def fake_test(self, host, port):
        return None
    monkeypatch.setattr(SmtpSmugglingPlugin, "_test_sequences", fake_test)
    assert await SmtpSmugglingPlugin().check(None, _host([_port()])) == []
