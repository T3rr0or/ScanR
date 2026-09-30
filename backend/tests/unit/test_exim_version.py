"""Exim MTA known-exploited version detection."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import exim_version as ev

PID = "services.exim_version"


def _b(banner):
    return ev.analyse_banner(banner, "192.0.2.5", 25, PID)


def test_parse_version_underscore_security_release():
    assert ev._parse_version("4.90_1") == (4, 90, 1)
    assert ev._parse_version("4.92.2") == (4, 92, 2)
    assert ev._parse_version("4.94") == (4, 94)


def test_old_exim_flags_base64_and_wizard_and_string_format():
    f = _b("220 mail ESMTP Exim 4.89 Ubuntu Mon, 01 Jan 2018 00:00:00 +0000")
    assert f is not None
    # 4.89 is < 4.90.1 (base64), in [4.87,4.92) (wizard), and < 4.70 is false.
    assert set(f.cve_ids) == {"CVE-2018-6789", "CVE-2019-10149"}
    assert f.severity is Severity.critical


def test_string_format_only_for_very_old():
    f = _b("220 old ESMTP Exim 4.69 ready")
    assert f is not None
    assert "CVE-2010-4344" in f.cve_ids
    assert "CVE-2018-6789" in f.cve_ids  # 4.69 < 4.90.1 too


def test_16928_range_is_bounded_below_and_above():
    # 4.92.1 is affected by CVE-2019-16928 (>=4.92, <4.92.3) and nothing else.
    f = _b("220 mail ESMTP Exim 4.92.1 ready")
    assert f is not None
    assert f.cve_ids == ["CVE-2019-16928"]
    assert f.severity is Severity.high


def test_patched_version_is_clean():
    assert _b("220 mail ESMTP Exim 4.92.3 ready") is None
    assert _b("220 mail ESMTP Exim 4.98 Debian ready") is None


def test_non_exim_banner_ignored():
    assert _b("220 mail.example.com ESMTP Postfix (Ubuntu)") is None
    assert _b("220 smtp ready") is None
    assert _b("") is None


def test_underscore_security_release_boundary():
    # 4.90 is affected by base64 (fixed 4.90.1); 4.90_1 == 4.90.1 is patched for it.
    assert "CVE-2018-6789" in _b("220 x ESMTP Exim 4.90 ready").cve_ids
    f = _b("220 x ESMTP Exim 4.90_1 ready")
    # 4.90.1 clears base64 but is still < 4.92 → wizard applies.
    assert f is not None
    assert "CVE-2018-6789" not in f.cve_ids
    assert "CVE-2019-10149" in f.cve_ids


@pytest.mark.asyncio
async def test_check_uses_existing_banner_without_network(monkeypatch):
    async def _boom(*a, **k):
        raise AssertionError("should not grab when banner already present")

    monkeypatch.setattr(ev, "grab_banner", _boom)
    port = SimpleNamespace(number=25, state="open", banner="220 ESMTP Exim 4.88 ready", service=None)
    host = SimpleNamespace(ip="192.0.2.5", hostname=None, ports=[port])
    findings = await ev.EximVersionPlugin().check(object(), host)
    assert len(findings) == 1
    assert findings[0].port_number == 25


@pytest.mark.asyncio
async def test_check_grabs_banner_when_absent(monkeypatch):
    async def _fake_grab(ip, port, use_ssl=False):
        return "220 mail ESMTP Exim 4.91 ready"

    monkeypatch.setattr(ev, "grab_banner", _fake_grab)
    port = SimpleNamespace(number=25, state="open", banner=None, service=None)
    host = SimpleNamespace(ip="192.0.2.5", hostname=None, ports=[port])
    findings = await ev.EximVersionPlugin().check(object(), host)
    assert len(findings) == 1
    assert "CVE-2019-10149" in findings[0].cve_ids
