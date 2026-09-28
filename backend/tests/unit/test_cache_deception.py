"""Web cache deception.

Pins the page-equivalence comparison (same dynamic page under a static URL,
tolerant of volatile tokens), the cache-hit detection and the public-cacheability
reading.
"""
from __future__ import annotations

from scanr.plugins.web.cache_deception import (
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
