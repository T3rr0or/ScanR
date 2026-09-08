"""Citrix ADC / NetScaler Gateway exposure."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import citrix_exposure as ce


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, handler):
    def factory(context):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ce, "_client", factory)


def _routes(pages: dict, default=(404, "not found", None)):
    """Serve `pages` by path; everything else gets `default`. Values are
    (status, text) or (status, text, headers)."""
    def handler(request):
        entry = pages.get(request.url.path, default)
        status, text, hdrs = (*entry, None)[:3] if len(entry) == 2 else entry
        return httpx.Response(status, text=text, headers=hdrs or {})
    return handler


def _host(port=443, state="open") -> SimpleNamespace:
    return SimpleNamespace(ip="192.0.2.70", hostname=None, ports=[SimpleNamespace(number=port, state=state, banner=None, service=None)])


async def _run(host):
    return await ce.CitrixExposurePlugin().check(_Ctx(), host)


# ── unauthenticated exposure ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_version_disclosure_is_reported_as_medium(monkeypatch):
    _install(monkeypatch, _routes({
        "/vpn/index.html": (200, '<script src="/vpn/js/rdx/rdx.js?v=13.1.30.6"></script> Citrix Gateway'),
        "/menu/neo": (404, "not found"),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.medium
    assert "13.1.30.6" in finding.title


@pytest.mark.asyncio
async def test_management_interface_reachable_is_reported_as_high(monkeypatch):
    _install(monkeypatch, _routes({
        "/vpn/index.html": (200, "Citrix Gateway logon", {"set-cookie": "NSC_AAAC=abcdef; path=/"}),
        "/menu/neo": (200, "<title>Configuration Utility</title> neo/main.html loads here"),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.title == "Citrix ADC / NetScaler Management Interface Reachable"
    assert finding.cvss_score == 8.6


# ── product present, authentication enforced ────────────────────────────────

@pytest.mark.asyncio
async def test_logon_endpoint_without_version_or_mgmt_is_reported_as_low(monkeypatch):
    _install(monkeypatch, _routes({
        "/vpn/index.html": (200, "Welcome to Citrix Gateway. Please log on."),
        "/menu/neo": (404, "not found"),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.low
    assert finding.title == "Citrix ADC / Gateway Logon Endpoint Detected"


# ── mandatory: unrelated web server produces nothing ────────────────────────

@pytest.mark.asyncio
async def test_unrelated_nginx_server_produces_nothing(monkeypatch):
    _install(monkeypatch, _routes({
        "/vpn/index.html": (404, "Not Found"),
        "/logon/LogonPoint/index.html": (404, "Not Found"),
        "/": (200, "<html><body><h1>Welcome to nginx!</h1></body></html>"),
    }))
    assert await _run(_host()) == []


@pytest.mark.asyncio
async def test_everything_404_produces_nothing(monkeypatch):
    _install(monkeypatch, _routes({}))
    assert await _run(_host()) == []


# ── mandatory: connection errors produce nothing, not an exception ─────────

@pytest.mark.asyncio
async def test_unreachable_host_produces_nothing(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")
    _install(monkeypatch, handler)
    assert await _run(_host()) == []
