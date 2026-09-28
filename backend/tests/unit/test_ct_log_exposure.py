"""Certificate Transparency log exposure.

Pins the crt.sh JSON parsing (untrusted third-party data is filtered to valid
in-scope hostnames) and the internal-name heuristic.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.ssl_tls.ct_log_exposure import (
    CtLogExposurePlugin,
    extract_names,
    sensitive_names,
)


def _host(hostname="www.example.com", ip="192.0.2.70"):
    return SimpleNamespace(ip=ip, hostname=hostname, ports=[])


# ── parsing untrusted CT data ────────────────────────────────────────────────

def test_extracts_in_scope_names_and_drops_others():
    rows = [
        {"name_value": "www.example.com\njenkins.example.com"},
        {"common_name": "*.staging.example.com"},
        {"name_value": "evil.attacker.net"},        # out of scope
        {"name_value": "not a hostname!!"},          # invalid
        "garbage-not-a-dict",
    ]
    names = extract_names(rows, "example.com")
    assert names == ["jenkins.example.com", "staging.example.com", "www.example.com"]


def test_non_list_input_is_handled():
    assert extract_names({"unexpected": "shape"}, "example.com") == []
    assert extract_names(None, "example.com") == []


def test_sensitive_names_flags_internal_labels():
    names = [
        "www.example.com", "jenkins.example.com", "vpn.example.com",
        "staging-api.example.com", "shop.example.com",
    ]
    flagged = sensitive_names(names, "example.com")
    assert "jenkins.example.com" in flagged
    assert "vpn.example.com" in flagged
    assert "staging-api.example.com" in flagged
    assert "shop.example.com" not in flagged
    assert "www.example.com" not in flagged


# ── plugin behaviour ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_flagged_names_raise_severity(monkeypatch):
    async def fake_query(self, domain):
        return ["www.example.com", "vault.example.com"]
    monkeypatch.setattr(CtLogExposurePlugin, "_query_ct_logs", fake_query)
    findings = await CtLogExposurePlugin().check(None, _host())
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"


@pytest.mark.asyncio
async def test_only_public_looking_names_is_info(monkeypatch):
    async def fake_query(self, domain):
        return ["www.example.com", "shop.example.com"]
    monkeypatch.setattr(CtLogExposurePlugin, "_query_ct_logs", fake_query)
    findings = await CtLogExposurePlugin().check(None, _host())
    assert findings[0].severity.value == "info"


@pytest.mark.asyncio
async def test_no_names_produces_nothing(monkeypatch):
    async def fake_query(self, domain):
        return []
    monkeypatch.setattr(CtLogExposurePlugin, "_query_ct_logs", fake_query)
    assert await CtLogExposurePlugin().check(None, _host()) == []


@pytest.mark.asyncio
async def test_bare_ip_target_is_skipped(monkeypatch):
    async def fail(self, domain):
        raise AssertionError("no domain to query")
    monkeypatch.setattr(CtLogExposurePlugin, "_query_ct_logs", fail)
    host = SimpleNamespace(ip="192.0.2.70", hostname="192.0.2.70", ports=[])
    assert await CtLogExposurePlugin().check(None, host) == []
