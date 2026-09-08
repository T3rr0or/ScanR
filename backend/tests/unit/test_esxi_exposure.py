"""VMware ESXi / vCenter management-interface exposure."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import esxi_exposure as ee


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, handler):
    def factory(context):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ee, "_client", factory)


def _routes(pages: dict, default=(404, "not found"), headers: dict | None = None):
    """Serve `pages` by path; everything else gets `default`. A tuple value
    is (status, text[, headers])."""
    def handler(request):
        entry = pages.get(request.url.path, default)
        status, text, hdrs = (*entry, None)[:3] if len(entry) == 2 else entry
        return httpx.Response(status, text=text, headers=hdrs or (headers or {}))
    return handler


def _host(port=443, state="open") -> SimpleNamespace:
    return SimpleNamespace(ip="192.0.2.60", hostname=None, ports=[SimpleNamespace(number=port, state=state, banner=None, service=None)])


async def _run(host):
    return await ee.EsxiExposurePlugin().check(_Ctx(), host)


# ── unauthenticated exposure ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_version_disclosure_is_reported_as_medium(monkeypatch):
    _install(monkeypatch, _routes({
        "/sdk/vimServiceVersions.xml": (200, "<namespace>urn:vim25</namespace><version>7.0.3.0</version>"),
        "/": (200, "<title>VMware ESXi</title>"),
        "/client/clients.xml": (200, "<clientconnection><version>7.0.3</version></clientconnection>"),
        "/folder": (404, "not found"),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.medium
    assert "7.0.3" in finding.title
    assert finding.port_number == 443


@pytest.mark.asyncio
async def test_datastore_browser_readable_is_reported_as_high(monkeypatch):
    """The worst case: /folder returns a real datastore listing pre-auth."""
    _install(monkeypatch, _routes({
        "/sdk/vimServiceVersions.xml": (200, "<namespace>urn:vim25</namespace>"),
        "/": (200, "<title>VMware ESXi</title>"),
        "/client/clients.xml": (404, "not found"),
        "/folder": (200, "Directory listing of /vmfs/volumes/abc dsPath=[datastore1]"),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert "Datastore Browser Readable" in finding.title
    assert finding.cvss_score == 8.6


@pytest.mark.asyncio
async def test_authd_banner_is_reported_as_low(monkeypatch):
    async def fake_tcp_probe(ip, port, read=256):
        return b"220 VMware Authentication Daemon Version 1.10: SSL Required\r\n"
    monkeypatch.setattr(ee, "_tcp_probe", fake_tcp_probe)

    findings = await _run(_host(port=902))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.low
    assert "authd" in finding.title.lower()
    assert "1.10" in finding.evidence


# ── product present, authentication enforced ────────────────────────────────

@pytest.mark.asyncio
async def test_auth_enforced_with_no_version_disclosed_is_reported_as_low(monkeypatch):
    _install(monkeypatch, _routes({
        "/sdk/vimServiceVersions.xml": (200, "<namespace>urn:vim25</namespace>"),
        "/": (200, "<title>VMware ESXi</title>"),
        "/client/clients.xml": (403, "Forbidden"),
        "/folder": (403, "Forbidden"),
    }))
    findings = await _run(_host())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.low
    assert finding.title == "VMware ESXi Management Interface Detected"


@pytest.mark.asyncio
async def test_authd_banner_without_the_version_string_produces_nothing(monkeypatch):
    async def fake_tcp_probe(ip, port, read=256):
        return b"220 some other ssh-ish banner\r\n"
    monkeypatch.setattr(ee, "_tcp_probe", fake_tcp_probe)
    assert await _run(_host(port=902)) == []


# ── mandatory: unrelated web server produces nothing ────────────────────────

@pytest.mark.asyncio
async def test_unrelated_nginx_server_produces_nothing(monkeypatch):
    _install(monkeypatch, _routes({
        "/sdk/vimServiceVersions.xml": (404, "Not Found"),
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


@pytest.mark.asyncio
async def test_authd_connection_error_produces_nothing(monkeypatch):
    async def fake_tcp_probe(ip, port, read=256):
        raise ConnectionRefusedError()
    monkeypatch.setattr(ee, "_tcp_probe", fake_tcp_probe)
    assert await _run(_host(port=902)) == []
