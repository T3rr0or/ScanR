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


def _host(hostname="example.com", ip="192.0.2.70"):
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

@pytest.mark.parametrize("hostname", [
    "app.example.co.uk", "example.co.uk", "app.example.com", "tenant.github.io",
])
def test_domain_preserves_supplied_scope(hostname):
    assert CtLogExposurePlugin._domain(None, _host(hostname)) == hostname


def test_domain_preserves_original_hostname_scope():
    context = SimpleNamespace(original_hostname=lambda ip: "*.App.Example.Co.Uk.")
    assert CtLogExposurePlugin._domain(context, _host(None)) == "app.example.co.uk"


@pytest.mark.asyncio
async def test_ct_response_excludes_unrelated_domains(monkeypatch):
    rows = [{"name_value": "\n".join([
        "app.example.co.uk", "www.app.example.co.uk", "vault.unrelated.co.uk",
        "vault.example.co.uk", "vault.notapp.example.co.uk",
    ])}]

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url, **kwargs):
            assert url == "https://crt.sh/?output=json&q=%25.app.example.co.uk"
            return SimpleNamespace(status_code=200, content=b"[]", json=lambda: rows)

    async def fake_client(url, **kwargs):
        return FakeClient()

    monkeypatch.setattr(
        "scanr.plugins.ssl_tls.ct_log_exposure.pinned_async_client", fake_client
    )
    findings = await CtLogExposurePlugin().check(None, _host("app.example.co.uk"))
    assert len(findings) == 1
    assert findings[0].severity.value == "info"
    assert "Distinct hostnames published: 2" in findings[0].evidence
    assert "www.app.example.co.uk" in findings[0].evidence
    assert "vault." not in findings[0].evidence


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
