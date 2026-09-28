"""Web cache deception.

Pins the page-equivalence comparison (same dynamic page under a static URL,
tolerant of volatile tokens), the cache-hit detection and the public-cacheability
reading.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from scanr.plugins.web import cache_deception
from scanr.plugins.web.cache_deception import (
    CacheDeceptionPlugin,
    bodies_match,
    build_probe_path,
    cache_hit_headers,
    publicly_cacheable,
)


def _page(token: str) -> str:
    return (
        "<html><head><title>My Account</title></head><body>"
        + "x" * 400 + f" csrf={token} </body></html>"
    )


def test_same_page_with_different_token_matches():
    assert bodies_match(_page("abc123def4567890"), _page("999888777666555444"))


def test_different_titles_do_not_match():
    other = "<html><head><title>404 Not Found</title></head><body>" + "y" * 400 + "</body></html>"
    assert not bodies_match(_page("abc123def4567890"), other)


def test_short_bodies_never_match():
    assert not bodies_match("<html>hi</html>", "<html>hi</html>")


def test_cache_hit_headers_detected():
    assert cache_hit_headers({"X-Cache": "HIT from edge"})
    assert cache_hit_headers({"Age": "42"})
    assert not cache_hit_headers({"X-Cache": "MISS", "Age": "0"})


def test_public_cacheability():
    assert publicly_cacheable({"Cache-Control": "public, max-age=60"})
    assert publicly_cacheable({})                       # no directive → heuristic storage
    assert not publicly_cacheable({"Cache-Control": "no-store, private"})
    assert not publicly_cacheable({"Cache-Control": "private"})


def test_build_probe_path_handles_root_and_subpaths():
    assert build_probe_path("/account", "/", "s.css") == "/account/s.css"
    assert build_probe_path("/", "/", "s.css") == "/s.css"
    assert build_probe_path("/", ";", "s.js") == "/;s.js"
    assert build_probe_path("/api/me", "%2f", "s.css") == "/api/me%2fs.css"


@pytest.mark.asyncio
async def test_probe_budget_reaches_private_routes(monkeypatch):
    @asynccontextmanager
    async def client_factory(*args, **kwargs):
        yield object()

    monkeypatch.setattr(cache_deception, "create_web_client", client_factory)
    plugin = CacheDeceptionPlugin()
    attempted = []

    async def get_baseline(client, url):
        return 200, {"content-type": "text/html"}, _page("abc123def4567890")

    async def record_probe(client, base_url, base_path, probe_path, baseline_body):
        attempted.append(base_path)
        return None

    monkeypatch.setattr(plugin, "_get", get_baseline)
    monkeypatch.setattr(plugin, "_confirm", record_probe)

    assert await plugin._probe_port(None, "https://example.com:443", "127.0.0.1", 443, "example.com") is None
    assert len(attempted) == cache_deception._MAX_PROBES
    assert set(cache_deception._BASE_PATHS).issubset(attempted[:len(cache_deception._BASE_PATHS)])
    assert attempted.index("/account") < attempted.index("/")


@pytest.mark.asyncio
async def test_noncacheable_root_does_not_exhaust_private_route_probes(monkeypatch):
    page = _page("abc123def4567890")
    requested = []

    class FakeClient:
        async def get(self, url, timeout):
            path = url.removeprefix("https://example.com:443")
            requested.append(path)
            headers = {"content-type": "text/html"}
            if path.startswith("/user/"):
                headers["x-cache"] = "HIT"
            elif path != "/user":
                headers["cache-control"] = "private, no-store"
            return SimpleNamespace(status_code=200, headers=headers, text=page)

    @asynccontextmanager
    async def client_factory(*args, **kwargs):
        yield FakeClient()

    monkeypatch.setattr(cache_deception, "create_web_client", client_factory)
    monkeypatch.setattr(cache_deception, "_BASE_PATHS", ("/", "/user"))

    evidence = await CacheDeceptionPlugin()._probe_port(
        None, "https://example.com:443", "127.0.0.1", 443, "example.com"
    )

    assert evidence is not None
    assert evidence.base_path == "/user"
    assert evidence.cached
    assert requested.index("/") < requested.index("/user")
    assert any(path.startswith("/scanr-") for path in requested)
    assert any(path.startswith("/user/scanr-") for path in requested)
