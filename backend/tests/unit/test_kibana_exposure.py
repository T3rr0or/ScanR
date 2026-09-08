"""Kibana exposure — /api/status version disclosure and the Elasticsearch
data plane it fronts."""
from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import kibana_exposure as ke


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, handler):
    def factory(context):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ke, "_client", factory)


def _routes(pages: dict, default=(404, "not found", None)):
    def handler(request):
        entry = pages.get(request.url.path, default)
        status, text, hdrs = (*entry, None)[:3] if len(entry) == 2 else entry
        return httpx.Response(status, text=text, headers=hdrs or {})
    return handler


def _host(port=5601, state="open") -> SimpleNamespace:
    return SimpleNamespace(ip="192.0.2.80", hostname=None, ports=[SimpleNamespace(number=port, state=state, banner=None, service=None)])


async def _run(host):
    return await ke.KibanaExposurePlugin().check(_Ctx(), host)


_STATUS_BODY = json.dumps({
    "name": "kibana-01",
    "version": {"number": "7.10.2"},
    "status": {"overall": {"level": "green"}},
})


# ── unauthenticated exposure ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_data_plane_access_is_reported_as_critical(monkeypatch):
    _install(monkeypatch, _routes({
        "/api/status": (200, _STATUS_BODY),
        "/api/saved_objects/_find": (200, '{"saved_objects": [{"id": "x"}], "total": 1}'),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.critical
    assert "7.10.2" in finding.title
    assert "Unauthenticated Access to Elasticsearch Data" in finding.title
    assert finding.cvss_score == 9.1


@pytest.mark.asyncio
async def test_status_disclosed_but_data_plane_blocked_is_reported_as_high(monkeypatch):
    _install(monkeypatch, _routes({
        "/api/status": (200, _STATUS_BODY),
        "/api/saved_objects/_find": (401, '{"statusCode":401}'),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert "7.10.2" in finding.title
    assert finding.title == "Kibana 7.10.2 Exposed Without Authentication"
    assert finding.cvss_score == 7.5


# ── product present, authentication enforced ────────────────────────────────

@pytest.mark.asyncio
async def test_auth_enforced_with_kbn_headers_is_reported_as_low(monkeypatch):
    _install(monkeypatch, _routes({
        "/api/status": (401, '{"statusCode":401}', {"kbn-name": "kibana", "kbn-version": "7.10.2"}),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.low
    assert finding.title == "Kibana Detected — Authentication Enforced"


@pytest.mark.asyncio
async def test_auth_enforced_confirmed_via_login_page_fallback(monkeypatch):
    """No kbn- headers on the 401 itself; the login page markers confirm it."""
    _install(monkeypatch, _routes({
        "/api/status": (401, "Unauthorized"),
        "/login": (200, '<div id="kbn-injected-metadata"></div>'),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    assert findings[0].severity is Severity.low


# ── mandatory: unrelated web server produces nothing ────────────────────────

@pytest.mark.asyncio
async def test_unrelated_nginx_server_produces_nothing(monkeypatch):
    _install(monkeypatch, _routes({
        "/api/status": (404, "Not Found"),
    }))
    assert await _run(_host()) == []


@pytest.mark.asyncio
async def test_generic_password_protected_server_produces_nothing(monkeypatch):
    """A bare 401 with no Kibana headers and no Kibana login page must not be
    mistaken for a hardened Kibana instance — any auth-gated site returns 401."""
    _install(monkeypatch, _routes({
        "/api/status": (401, "Unauthorized"),
        "/login": (404, "Not Found"),
    }))
    assert await _run(_host()) == []


@pytest.mark.asyncio
async def test_non_kibana_json_status_endpoint_produces_nothing(monkeypatch):
    """A generic {"status":"ok"} health check must not read as Kibana's
    version-bearing status document."""
    _install(monkeypatch, _routes({
        "/api/status": (200, '{"status": "ok"}'),
    }))
    assert await _run(_host()) == []


# ── mandatory: connection errors produce nothing, not an exception ─────────

@pytest.mark.asyncio
async def test_unreachable_host_produces_nothing(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")
    _install(monkeypatch, handler)
    assert await _run(_host()) == []
