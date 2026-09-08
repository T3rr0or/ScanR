"""CUPS web interface exposure detection (TCP 631).

Pins CUPS identification (a Server: CUPS banner, or the paired body markers —
never a bare mention of "cups"), and that the plugin only reports when a page
actually came back 200: a CUPS instance that answers every path with
401/403/426 is correctly locked down and produces nothing.
"""
from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import cups_exposure as ce


def _port(number, state="open"):
    return SimpleNamespace(number=number, state=state, banner=None, service=None)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, handler):
    """Route every httpx.AsyncClient the plugin creates through a MockTransport,
    regardless of the scheme/kwargs it was constructed with (verify=, timeout=,
    follow_redirects=, proxy kwargs). Captures the real class first — the plugin
    module and this test both see the same `httpx` module object, so patching
    its `AsyncClient` attribute in place would otherwise make the factory call
    itself."""
    real_async_client = httpx.AsyncClient

    def factory(*_a, **_kw):
        return real_async_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(ce.httpx, "AsyncClient", factory)


def _routes(pages: dict, default=404, server=None):
    """Serve `pages` by path. Entry may be a body string (-> 200) or (status, body)."""
    def handler(request):
        headers = {"server": server} if server else {}
        entry = pages.get(request.url.path)
        if entry is None:
            return httpx.Response(default, text="not found", headers=headers)
        if isinstance(entry, tuple):
            status, body = entry
            return httpx.Response(status, text=body, headers=headers)
        return httpx.Response(200, text=entry, headers=headers)
    return handler


def _unreachable(_request):
    raise httpx.ConnectError("connection refused")


# ── CUPS identification ──────────────────────────────────────────────────────

def test_server_banner_alone_is_enough():
    assert ce._is_cups(401, {"server": "CUPS/2.4.7"}, "") is True


def test_body_needs_both_markers_paired():
    body = "<html>CUPS 2.4.7 - Common UNIX Printing System</html>"
    assert ce._is_cups(200, {}, body) is True


def test_bare_mention_of_cups_is_not_enough():
    """A random app that merely says 'cups' somewhere must not be misidentified."""
    assert ce._is_cups(200, {}, "<html>We sell travel cups and mugs</html>") is False


def test_non_200_without_banner_is_not_confirmed():
    assert ce._is_cups(404, {}, "Common UNIX Printing System, cups.org") is False


# ── plugin behaviour ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_open_admin_interface_is_reported_high(monkeypatch):
    _install(monkeypatch, _routes(
        {
            "/": "<html>CUPS 2.4.7 - Common UNIX Printing System</html>",
            "/admin": "<html>CUPS Administration</html>",
            "/printers": "<html>Printers</html>",
            "/jobs": "<html>Jobs</html>",
        },
        server="CUPS/2.4",
    ))
    host = _host([_port(631)])

    findings = await ce.CupsExposurePlugin().check(_Ctx(), host)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.title == "CUPS Administration Interface Reachable Without Authentication"
    assert "/admin" in finding.evidence
    assert finding.port_number == 631
    assert finding.protocol == "tcp"


@pytest.mark.asyncio
async def test_admin_protected_but_printers_open_is_medium(monkeypatch):
    _install(monkeypatch, _routes(
        {
            "/": "<html>CUPS 2.4.7 - Common UNIX Printing System</html>",
            "/admin": (401, "Unauthorized"),
            "/printers": "<html>Printers</html>",
            "/jobs": (401, "Unauthorized"),
        },
        server="CUPS/2.4",
    ))
    host = _host([_port(631)])

    findings = await ce.CupsExposurePlugin().check(_Ctx(), host)

    assert len(findings) == 1
    assert findings[0].severity is Severity.medium
    assert findings[0].title == "CUPS Web Interface Reachable Without Authentication"


@pytest.mark.asyncio
async def test_fully_locked_down_cups_produces_no_finding(monkeypatch):
    """The daemon is real CUPS (banner confirms it) but every page is 401/403/426."""
    _install(monkeypatch, _routes(
        {
            "/": (401, "Unauthorized"),
            "/admin": (401, "Unauthorized"),
            "/printers": (403, "Forbidden"),
            "/jobs": (426, "Upgrade Required"),
        },
        server="CUPS/2.4",
    ))
    host = _host([_port(631)])

    assert await ce.CupsExposurePlugin().check(_Ctx(), host) == []


@pytest.mark.asyncio
async def test_closed_port_is_skipped_without_probing(monkeypatch):
    _install(monkeypatch, _unreachable)  # would raise if ever called
    host = _host([_port(631, state="closed")])

    assert await ce.CupsExposurePlugin().check(_Ctx(), host) == []


@pytest.mark.asyncio
async def test_unreachable_port_produces_no_finding_and_no_exception(monkeypatch):
    _install(monkeypatch, _unreachable)
    host = _host([_port(631)])

    assert await ce.CupsExposurePlugin().check(_Ctx(), host) == []


@pytest.mark.asyncio
async def test_non_cups_service_produces_no_finding(monkeypatch):
    """A plain web server (or something else entirely) answering on 631 must
    never be reported as an exposed CUPS interface."""
    _install(monkeypatch, _routes({"/": "<html><body>It works!</body></html>"}, server="Apache/2.4.41"))
    host = _host([_port(631)])

    assert await ce.CupsExposurePlugin().check(_Ctx(), host) == []
