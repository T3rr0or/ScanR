"""Portainer exposure and unclaimed-instance detection.

The dangerous mistake this check could make is reading a 404 from
/api/users/admin/check as "no admin account exists" on something that is not
Portainer at all — a web server that 404s every unknown path would then be
reported as a critical, claimable Docker host. So the tests pin that positive
fingerprinting from Portainer's own status document comes first, and that a
document carrying only a generic "Version" key does not qualify.
"""
import json
from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import portainer_exposure as pe


def _port(number, state="open"):
    return SimpleNamespace(number=number, state=state, banner=None, service=None)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, handler):
    """Route every client the plugin builds through a MockTransport. The real
    class is captured first: the plugin module and this test share one `httpx`
    module object, so patching the attribute in place would otherwise make the
    factory recurse into itself."""
    real_async_client = httpx.AsyncClient

    def factory(*_a, **_kw):
        return real_async_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(pe.httpx, "AsyncClient", factory)


def _routes(pages: dict, default=404):
    """Serve `pages` by path. Entry may be a body string (-> 200) or (status, body)."""
    def handler(request):
        entry = pages.get(request.url.path)
        if entry is None:
            return httpx.Response(default, text="not found")
        if isinstance(entry, tuple):
            status, body = entry
            return httpx.Response(status, text=body)
        return httpx.Response(200, text=entry)
    return handler


def _unreachable(_request):
    raise httpx.ConnectError("connection refused")


PORTAINER_STATUS = json.dumps({
    "Version": "2.19.4",
    "InstanceID": "8f4b3f7a-1c2d-4e5f-9a8b-7c6d5e4f3a2b",
    "DemoEnvironment": {"Enabled": False, "Environments": []},
})
PORTAINER_STATUS_1X = json.dumps({
    "Authentication": True,
    "EndpointManagement": True,
    "Version": "1.24.1",
})


# ── fingerprinting ───────────────────────────────────────────────────────────

def test_portainer_status_document_is_recognised():
    assert pe._is_portainer_status(json.loads(PORTAINER_STATUS)) is True
    assert pe._is_portainer_status(json.loads(PORTAINER_STATUS_1X)) is True


@pytest.mark.parametrize("data", [
    None,
    {},
    {"Version": "1.0"},                       # some other app's /api/status
    {"Version": "1.0", "status": "healthy"},  # ditto, with a health field
    {"InstanceID": "abc"},                    # no version at all
])
def test_a_generic_status_document_is_not_portainer(data):
    assert pe._is_portainer_status(data) is False


def test_version_is_read_case_insensitively():
    assert pe._version_of({"version": "2.20.0"}) == "2.20.0"
    assert pe._version_of({"Version": 2}) == ""
    assert pe._version_of(None) == ""


# ── plugin behaviour: the critical case ──────────────────────────────────────

@pytest.mark.asyncio
async def test_unclaimed_instance_is_critical(monkeypatch):
    _install(monkeypatch, _routes({
        "/api/status": PORTAINER_STATUS,
        # 404 here is Portainer saying no administrator account exists yet.
        "/api/users/admin/check": (404, '{"message":"Object not found inside the database"}'),
    }))

    findings = await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.critical
    assert finding.title == "Portainer 2.19.4 Instance Is Unclaimed — No Admin Account Created"
    assert "/api/users/admin/check -> HTTP 404" in finding.evidence
    assert "2.19.4" in finding.evidence
    # The mechanism — first-comer creates the admin and owns the Docker host —
    # is the whole reason this outranks a plain exposure finding.
    assert "create the first administrator account" in finding.description
    assert "host filesystem" in finding.description
    assert finding.cvss_score == 9.8
    assert finding.port_number == 9000
    assert finding.protocol == "tcp"


@pytest.mark.asyncio
async def test_status_under_the_system_prefix_is_used_as_a_fallback(monkeypatch):
    """2.18 moved the endpoint to /api/system/status."""
    _install(monkeypatch, _routes({
        "/api/system/status": PORTAINER_STATUS,
        "/api/users/admin/check": (404, '{"message":"Object not found inside the database"}'),
    }))

    findings = await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9443)]))

    assert len(findings) == 1
    assert findings[0].severity is Severity.critical


# ── plugin behaviour: exposure only ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_instance_with_an_admin_is_exposure_only(monkeypatch):
    _install(monkeypatch, _routes({
        "/api/status": PORTAINER_STATUS,
        "/api/users/admin/check": (204, ""),
    }))

    findings = await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.medium
    assert finding.title == "Portainer 2.19.4 Management Interface Exposed"
    assert "cannot be claimed" in finding.description
    assert finding.cvss_score is None


@pytest.mark.asyncio
async def test_admin_check_behind_auth_is_not_treated_as_unclaimed(monkeypatch):
    """A 401/403 does not say whether an admin exists — do not guess 'unclaimed'."""
    _install(monkeypatch, _routes({
        "/api/status": PORTAINER_STATUS,
        "/api/users/admin/check": (401, '{"message":"unauthorized"}'),
    }))

    findings = await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)]))

    assert len(findings) == 1
    assert findings[0].severity is Severity.medium
    assert "could not be determined" in findings[0].description


@pytest.mark.asyncio
async def test_html_404_from_a_proxy_is_not_treated_as_unclaimed(monkeypatch):
    """A reverse proxy's HTML error page in front of the API is not Portainer
    reporting its setup state; Portainer answers this endpoint with JSON."""
    _install(monkeypatch, _routes({
        "/api/status": PORTAINER_STATUS,
        "/api/users/admin/check": (404, "<!DOCTYPE html><html><body>404 Not Found</body></html>"),
    }))

    findings = await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)]))

    assert len(findings) == 1
    assert findings[0].severity is Severity.medium


@pytest.mark.asyncio
async def test_version_disclosure_is_called_out_when_present(monkeypatch):
    _install(monkeypatch, _routes({
        "/api/status": PORTAINER_STATUS_1X,
        "/api/users/admin/check": (204, ""),
    }))

    findings = await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)]))

    assert "1.24.1" in findings[0].description


# ── plugin behaviour: the false-positive traps ───────────────────────────────

@pytest.mark.asyncio
async def test_a_server_that_404s_everything_is_not_an_unclaimed_portainer(monkeypatch):
    """The dangerous one: a blanket 404 must never read as 'no admin exists'."""
    _install(monkeypatch, _routes({}, default=404))

    assert await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)])) == []


@pytest.mark.asyncio
async def test_unrelated_api_with_a_version_key_is_not_portainer(monkeypatch):
    """Positive fingerprinting is required before the admin check is believed."""
    _install(monkeypatch, _routes({
        "/api/status": json.dumps({"Version": "1.0", "status": "ok"}),
        "/api/users/admin/check": (404, '{"error":"unknown route"}'),
    }))

    assert await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)])) == []


@pytest.mark.asyncio
async def test_plain_web_server_on_the_port_is_not_reported(monkeypatch):
    _install(monkeypatch, _routes({
        "/api/status": "<html><body>It works!</body></html>",
        "/api/system/status": "<html><body>It works!</body></html>",
    }))

    assert await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9443)])) == []


@pytest.mark.asyncio
async def test_status_answering_non_200_is_not_fingerprinted(monkeypatch):
    _install(monkeypatch, _routes({
        "/api/status": (503, PORTAINER_STATUS),
        "/api/system/status": (503, PORTAINER_STATUS),
    }))

    assert await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)])) == []


# ── plugin behaviour: nothing to talk to ─────────────────────────────────────

@pytest.mark.asyncio
async def test_closed_port_is_skipped_without_probing(monkeypatch):
    _install(monkeypatch, _unreachable)  # would raise if ever called

    assert await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000, state="closed")])) == []


@pytest.mark.asyncio
async def test_unreachable_port_produces_no_finding_and_no_exception(monkeypatch):
    _install(monkeypatch, _unreachable)

    assert await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)])) == []


# ── read-only guarantees ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_only_get_requests_are_sent_and_never_to_admin_init(monkeypatch):
    seen: list[tuple[str, str]] = []

    def handler(request):
        seen.append((request.method, request.url.path))
        if request.url.path == "/api/status":
            return httpx.Response(200, text=PORTAINER_STATUS)
        return httpx.Response(404, text='{"message":"Object not found inside the database"}')

    _install(monkeypatch, handler)
    await pe.PortainerExposurePlugin().check(_Ctx(), _host([_port(9000)]))

    assert seen and all(method == "GET" for method, _ in seen)
    assert not any("init" in path for _, path in seen)
    assert pe.PortainerExposurePlugin.intrusive is False
    assert pe.PortainerExposurePlugin.destructive is False
