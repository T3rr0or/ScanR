"""Apache Airflow exposure — unauthenticated DAG / connection listing via the
REST API."""
from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import airflow_exposure as ae


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, handler):
    def factory(context):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ae, "_client", factory)


def _routes(pages: dict, default=(404, "not found", None)):
    def handler(request):
        entry = pages.get(request.url.path, default)
        status, text, hdrs = (*entry, None)[:3] if len(entry) == 2 else entry
        return httpx.Response(status, text=text, headers=hdrs or {})
    return handler


def _host(port=8080, state="open") -> SimpleNamespace:
    return SimpleNamespace(ip="192.0.2.90", hostname=None, ports=[SimpleNamespace(number=port, state=state, banner=None, service=None)])


async def _run(host):
    return await ae.AirflowExposurePlugin().check(_Ctx(), host)


_HEALTH_BODY = json.dumps({
    "metadatabase": {"status": "healthy"},
    "scheduler": {"status": "healthy"},
})
_LOGIN_BODY = '<title>Sign in - Airflow</title><link href="/static/appbuilder/css/x.css"> Apache Airflow v2.7.1'


# ── unauthenticated exposure ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_connections_listing_is_reported_as_critical(monkeypatch):
    _install(monkeypatch, _routes({
        "/health": (200, _HEALTH_BODY),
        "/login/": (200, _LOGIN_BODY),
        "/api/v1/connections": (200, json.dumps({"connections": [{"connection_id": "aws_default"}], "total_entries": 5})),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.critical
    assert "Unauthenticated Access to Orchestration Connections" in finding.title
    assert "2.7.1" in finding.title
    assert finding.cvss_score == 9.8


@pytest.mark.asyncio
async def test_unauthenticated_dag_listing_is_reported_as_critical(monkeypatch):
    _install(monkeypatch, _routes({
        "/health": (200, _HEALTH_BODY),
        "/login/": (200, _LOGIN_BODY),
        "/api/v1/connections": (403, "Forbidden"),
        "/api/v1/dags": (200, json.dumps({"dags": [{"dag_id": "etl_pipeline"}], "total_entries": 12})),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.critical
    assert "Unauthenticated DAG Listing" in finding.title


# ── product present, authentication enforced ────────────────────────────────

@pytest.mark.asyncio
async def test_auth_enforced_with_version_is_reported_as_medium(monkeypatch):
    _install(monkeypatch, _routes({
        "/health": (403, "Forbidden"),
        "/login/": (200, _LOGIN_BODY),
        "/api/v1/connections": (403, "Forbidden"),
        "/api/v1/dags": (403, "Forbidden"),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.medium
    assert "2.7.1" in finding.title
    assert "Authentication Enforced" in finding.title


@pytest.mark.asyncio
async def test_auth_enforced_without_version_is_reported_as_low(monkeypatch):
    _install(monkeypatch, _routes({
        "/health": (403, "Forbidden"),
        "/login/": (200, '<link href="/static/appbuilder/css/x.css"> sign in please'),
        "/api/v1/connections": (403, "Forbidden"),
        "/api/v1/dags": (403, "Forbidden"),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    assert findings[0].severity is Severity.low


# ── mandatory: unrelated web server produces nothing ────────────────────────

@pytest.mark.asyncio
async def test_unrelated_nginx_server_produces_nothing(monkeypatch):
    _install(monkeypatch, _routes({
        "/health": (404, "Not Found"),
        "/login/": (200, "<html><body><h1>Welcome to nginx!</h1></body></html>"),
    }))
    assert await _run(_host()) == []


@pytest.mark.asyncio
async def test_generic_json_health_endpoint_produces_nothing(monkeypatch):
    """A plain {"status":"ok"} health check on an unrelated app must not be
    read as Airflow's component-named health document."""
    _install(monkeypatch, _routes({
        "/health": (200, '{"status": "ok"}'),
        "/login/": (404, "Not Found"),
    }))
    assert await _run(_host()) == []


# ── mandatory: connection errors produce nothing, not an exception ─────────

@pytest.mark.asyncio
async def test_unreachable_host_produces_nothing(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")
    _install(monkeypatch, handler)
    assert await _run(_host()) == []
