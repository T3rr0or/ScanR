"""CRLF injection / HTTP response splitting.

The only signal the plugin trusts is a header httpx's own parser produced —
`resp.headers[...]`, never the response body. The false-positive trap below
(a payload reflected verbatim into the page text, with no real header set) is
exactly the case that distinction exists to rule out: grepping a body for a
`%0d%0a` echo is the standard way this class of check produces noise.
"""
from __future__ import annotations

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.web import crlf_injection as ci
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
    monkeypatch.setattr(ci, "crawl", fake_crawl)


def _install(monkeypatch, handler):
    def factory(*_a, **_kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ci, "create_web_client", factory)


async def _run(base="http://192.0.2.10:80"):
    return await ci.CrlfInjectionPlugin()._test_host(_Ctx(), base, 80)


def _vulnerable_handler(request):
    """A server that splits a header on CR/LF found anywhere in a query value.

    httpx decodes the request's percent-encoded query on the way in, so a
    value of "\\r\\nX-ScanR-Injected: <token>" arrives already unescaped --
    this mimics a backend that does the same before writing the header.
    """
    for _key, value in request.url.params.multi_items():
        if "\r" in value or "\n" in value:
            lines = value.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            headers = {}
            for line in lines[1:]:
                name, sep, val = line.partition(":")
                if sep:
                    headers[name.strip()] = val.strip()
            if headers:
                return httpx.Response(200, text="ok", headers=headers)
    return httpx.Response(200, text="<html>no injection here</html>")


# ── true positive ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_injected_header_observed_in_parsed_response_headers_is_reported(monkeypatch):
    _install(monkeypatch, _vulnerable_handler)
    finding = await _run()

    assert finding is not None
    assert finding.severity is Severity.high
    assert finding.title == "CRLF Injection (HTTP Response Splitting)"
    assert "X-ScanR-Injected" in finding.evidence
    assert "parsed response" in finding.evidence


# ── false-positive trap: body reflection is not a header ────────────────────

@pytest.mark.asyncio
async def test_payload_reflected_in_the_body_but_not_a_real_header_is_not_reported(monkeypatch):
    """The server echoes the raw query string into the page. No header was
    ever set, so httpx's parsed `resp.headers` never contains the marker --
    and that, not the body text, is what the plugin looks at."""
    def handler(request):
        raw_query = request.url.query.decode(errors="replace")
        return httpx.Response(200, text=f"<html>You searched for: {raw_query}</html>")

    _install(monkeypatch, handler)
    assert await _run() is None


# ── clean server ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_server_produces_nothing(monkeypatch):
    _install(monkeypatch, lambda r: httpx.Response(200, text="<html>hello</html>"))
    assert await _run() is None


@pytest.mark.asyncio
async def test_connection_errors_do_not_propagate(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")

    _install(monkeypatch, handler)
    assert await _run() is None
