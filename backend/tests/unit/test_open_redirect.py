"""The open-redirect plugin's reporting path.

The branch that returns a finding was previously unreachable — the true-positive
case fell through to the next loop iteration and the `return` sat after an
unconditional `continue` — so the plugin silently reported nothing for its whole
vulnerability class no matter how the target behaved.
"""
import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.web.open_redirect import OpenRedirectPlugin


class _Ctx:
    def proxy_config(self):
        return {}


def _client_returning(handler):
    """Patch httpx.AsyncClient so the plugin talks to `handler` instead of a socket."""
    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient

    def factory(*_args, **kwargs):
        kwargs.pop("verify", None)
        kwargs.pop("proxy", None)
        return real(transport=transport, **kwargs)

    return factory


@pytest.mark.asyncio
async def test_reports_when_location_host_is_attacker_controlled(monkeypatch):
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://evil.example.com/x"})

    monkeypatch.setattr(httpx, "AsyncClient", _client_returning(handler))
    finding = await OpenRedirectPlugin()._test_redirects(_Ctx(), "192.0.2.10", 80, "http")

    assert finding is not None, "a redirect to the canary host must be reported"
    assert finding.severity is Severity.medium
    assert "evil.example.com" in finding.evidence


@pytest.mark.asyncio
async def test_same_origin_bounce_carrying_the_canary_is_not_reported(monkeypatch):
    """A login bounce echoing the canary in its query is not a redirect we control."""
    def handler(request):
        return httpx.Response(
            302, headers={"Location": "/login?next=https://evil.example.com"}
        )

    monkeypatch.setattr(httpx, "AsyncClient", _client_returning(handler))
    assert await OpenRedirectPlugin()._test_redirects(_Ctx(), "192.0.2.10", 80, "http") is None


@pytest.mark.asyncio
async def test_no_redirect_is_not_reported(monkeypatch):
    def handler(request):
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _client_returning(handler))
    assert await OpenRedirectPlugin()._test_redirects(_Ctx(), "192.0.2.10", 80, "http") is None


@pytest.mark.asyncio
async def test_redirect_to_an_unrelated_host_is_not_reported(monkeypatch):
    def handler(request):
        return httpx.Response(302, headers={"Location": "https://cdn.example.net/"})

    monkeypatch.setattr(httpx, "AsyncClient", _client_returning(handler))
    assert await OpenRedirectPlugin()._test_redirects(_Ctx(), "192.0.2.10", 80, "http") is None
