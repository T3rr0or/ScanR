"""Missing Subresource Integrity on third-party scripts and stylesheets.

Scope is the whole check: SRI on a same-origin asset protects nothing (whoever
can rewrite the script can rewrite the page's hash right along with it), so
same-origin references must never be reported -- that is the false-positive
trap below. Everything cross-origin without `integrity=` is real exposure, and
splits on transport (http vs https) because the attacker capability required
is very different.
"""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.web import sri_missing as sri
from scanr.plugins.web._crawler import CrawlResult


class _Ctx:
    def proxy_config(self):
        return {}

    def web_auth_headers(self):
        return {}


@pytest.fixture(autouse=True)
def _no_crawl(monkeypatch):
    async def fake_crawl(base_url, client):
        return CrawlResult(paths=["/"], get_params=[])
    monkeypatch.setattr(sri, "crawl", fake_crawl)


def _install(monkeypatch, handler):
    def factory(*_a, **_kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(sri, "create_web_client", factory)


def _host(port=80, state="open"):
    return SimpleNamespace(
        ip="192.0.2.10", hostname=None,
        ports=[SimpleNamespace(number=port, state=state)],
    )


def _page(handler_html: str):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200, text=handler_html, headers={"content-type": "text/html"}
            )
        return httpx.Response(404, text="not found")
    return handler


async def _run(monkeypatch, html: str):
    _install(monkeypatch, _page(html))
    return await sri.SriMissingPlugin().check(_Ctx(), _host())


# ── third-party without integrity ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_third_party_script_without_integrity_is_reported(monkeypatch):
    html = '<html><body><script src="https://cdn.example.net/lib.js"></script></body></html>'
    findings = await _run(monkeypatch, html)

    assert len(findings) == 1
    assert findings[0].severity is Severity.low
    assert "cdn.example.net" in findings[0].evidence


# ── false-positive trap: same-origin needs no SRI ────────────────────────────

@pytest.mark.asyncio
async def test_same_origin_script_without_integrity_is_not_reported(monkeypatch):
    """A relative path resolves to the page's own host -- SRI adds nothing
    there, since whoever controls the origin controls both the script and any
    hash the page would check it against."""
    html = '<html><body><script src="/static/app.js"></script></body></html>'
    findings = await _run(monkeypatch, html)
    assert findings == []


# ── integrity present ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_third_party_script_with_integrity_is_not_reported(monkeypatch):
    html = (
        '<html><body><script src="https://cdn.example.net/lib.js" '
        'integrity="sha384-abc123" crossorigin="anonymous"></script></body></html>'
    )
    findings = await _run(monkeypatch, html)
    assert findings == []


# ── transport affects severity ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_http_and_https_third_party_scripts_are_scored_differently(monkeypatch):
    html = (
        '<html><body>'
        '<script src="http://plaintext-cdn.example.net/legacy.js"></script>'
        '<script src="https://encrypted-cdn.example.org/lib.js"></script>'
        '</body></html>'
    )
    findings = await _run(monkeypatch, html)

    assert len(findings) == 2
    http_finding = next(f for f in findings if "plaintext-cdn.example.net" in f.evidence)
    https_finding = next(f for f in findings if "encrypted-cdn.example.org" in f.evidence)

    assert http_finding.severity is Severity.medium
    assert https_finding.severity is Severity.low
    assert http_finding.cvss_score > https_finding.cvss_score
    assert "over plaintext HTTP" in http_finding.title
    assert "over HTTPS" in https_finding.title
