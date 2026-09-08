"""CORS severity turns on one question: can another origin read a *credentialed*
response?

A wildcard alone cannot — browsers refuse to send credentials to
`Access-Control-Allow-Origin: *`, so it is how every CDN and public API serves
assets. Reporting it as high severity fired on a real host during network
validation and would fire on most of the web.
"""
import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.web import cors_misconfig as cm


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, headers):
    real = httpx.AsyncClient

    def factory(*_a, **kw):
        kw.pop("verify", None)
        kw.pop("proxy", None)
        return real(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, headers=headers, text="ok")), **kw)

    monkeypatch.setattr(cm.httpx, "AsyncClient", factory)


async def _check(monkeypatch, headers):
    _install(monkeypatch, headers)
    return await cm.CorsMisconfigPlugin()._check_cors(_Ctx(), "http://192.0.2.10/")


@pytest.mark.asyncio
async def test_wildcard_without_credentials_is_informational(monkeypatch):
    """The normal public-asset configuration is not a vulnerability."""
    r = await _check(monkeypatch, {"access-control-allow-origin": "*"})
    assert r["severity"] is Severity.info


@pytest.mark.asyncio
async def test_wildcard_with_credentials_is_low_not_high(monkeypatch):
    """Browsers reject the pair, so it is a policy smell rather than a hole."""
    r = await _check(monkeypatch, {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    })
    assert r["severity"] is Severity.low


@pytest.mark.asyncio
async def test_reflected_origin_with_credentials_is_high(monkeypatch):
    """The dangerous shape: any site can read the victim's authenticated data."""
    r = await _check(monkeypatch, {
        "access-control-allow-origin": "https://evil.example.com",
        "access-control-allow-credentials": "true",
    })
    assert r["severity"] is Severity.high
    assert "credentials" in r["description"].lower()


@pytest.mark.asyncio
async def test_reflected_origin_without_credentials_is_medium(monkeypatch):
    r = await _check(monkeypatch, {"access-control-allow-origin": "https://evil.example.com"})
    assert r["severity"] is Severity.medium


@pytest.mark.asyncio
async def test_a_server_with_no_cors_headers_is_not_reported(monkeypatch):
    assert await _check(monkeypatch, {}) is None


@pytest.mark.asyncio
async def test_an_allowlisted_origin_is_not_reported(monkeypatch):
    """Echoing a *different* origin than we sent means it is validating."""
    r = await _check(monkeypatch, {
        "access-control-allow-origin": "https://app.trusted.example",
        "access-control-allow-credentials": "true",
    })
    assert r is None
