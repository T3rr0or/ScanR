"""JavaScript source map exposure.

Pins the same-origin script extraction, map-candidate derivation, source-map
parsing (only a JSON object with a sources array counts) and the secret scan.
"""
from __future__ import annotations

import asyncio
import base64
import json
from urllib.parse import quote

import httpx
import pytest

from scanr.plugins.web import source_map_exposure as module
from scanr.plugins.web.source_map_exposure import (
    SourceMap,
    SourceMapExposurePlugin,
    decode_inline_map,
    extract_script_urls,
    find_secrets,
    map_candidates,
    parse_source_map,
)


def test_extract_script_urls_is_same_origin_and_js_only():
    html = (
        '<script src="/static/app.min.js"></script>'
        '<script src="https://cdn.other.net/x.js"></script>'
        '<script src="/style.css"></script>'
    )
    urls = extract_script_urls(html, "https://app.example:443/")
    assert urls == ["https://app.example:443/static/app.min.js"]


def test_map_candidates_prefers_declared_then_convention():
    assert map_candidates("https://t/app.js", "//# sourceMappingURL=app.js.map") == [
        "https://t/app.js.map"
    ]
    # No comment → conventional .map only.
    assert map_candidates("https://t/app.js?v=1", "no comment") == ["https://t/app.js.map"]


def test_inline_data_map_preserves_payload_for_local_decoding():
    cands = map_candidates("https://t/app.js", "//# sourceMappingURL=data:application/json;base64,eyj")
    assert cands == ["data:application/json;base64,eyj", "https://t/app.js.map"]


def test_parse_source_map_requires_a_sources_array():
    parsed = parse_source_map('{"version":3,"sources":["src/a.ts"],"sourcesContent":["x"]}')
    assert parsed == (["src/a.ts"], True)
    assert parse_source_map('{"version":3,"sources":["src/a.ts"]}') == (["src/a.ts"], False)


def test_parse_source_map_rejects_non_maps():
    assert parse_source_map("<html>404</html>") is None
    assert parse_source_map('{"data":[]}') is None
    assert parse_source_map("[1,2,3]") is None


def test_find_secrets_matches_credential_formats():
    # Assemble the sample credentials at runtime so no literal that looks like a
    # real key sits in the source tree (push-protection / secret scanners).
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    stripe = "sk_" + "live_" + "a" * 24
    body = f'const k="{aws}"; const s="{stripe}";'
    found = find_secrets(body)
    assert any("AWS" in f for f in found)
    assert any("Stripe" in f for f in found)


def test_finding_severity_tracks_what_was_recovered():
    plugin = SourceMapExposurePlugin()
    only_paths = [SourceMap(url="u", script_url="s", sources=["a"], has_contents=False)]
    with_contents = [SourceMap(url="u", script_url="s", sources=["a"], has_contents=True)]
    with_secrets = [SourceMap(url="u", script_url="s", sources=["a"], has_contents=True,
                              secrets=["AWS access key id x1"])]
    assert plugin._build_finding(only_paths, 443).severity.value == "low"
    assert plugin._build_finding(with_contents, 443).severity.value == "medium"
    assert plugin._build_finding(with_secrets, 443).severity.value == "high"


class MapClient:
    def __init__(self, script, external=None):
        self.responses = {
            "https://t:443/": httpx.Response(200, text='<script src="/app.js"></script>',
                                            headers={"content-type": "text/html"}),
            "https://t:443/app.js": httpx.Response(200, text=script),
        }
        if external is not None:
            self.responses["https://t:443/app.js.map"] = httpx.Response(200, text=external)
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url, **kwargs):
        self.requests.append(url)
        return self.responses.get(url, httpx.Response(404))


def collect(monkeypatch, client):
    monkeypatch.setattr(module, "create_web_client", lambda *args, **kwargs: client)
    return asyncio.run(SourceMapExposurePlugin()._collect(None, "https://t:443", "127.0.0.1", 443, "t"))


@pytest.mark.parametrize("encoding", ["base64", "percent"])
def test_inline_maps_recover_large_contents_and_secrets_without_second_request(monkeypatch, encoding):
    secret = "sk_" + "live_" + "a" * 24
    body = json.dumps({"version": 3, "sources": ["src/private.ts"],
                       "sourcesContent": ["//" + "x" * 5000 + "\nconst key='" + secret + "';"]})
    if encoding == "base64":
        uri = "data:application/json;charset=utf-8;base64," + base64.b64encode(body.encode()).decode()
    else:
        uri = "data:application/json," + quote(body, safe="")
    client = MapClient("console.log('app');\n//# sourceMappingURL=" + uri)
    maps = collect(monkeypatch, client)
    assert len(maps) == 1
    assert maps[0].sources == ["src/private.ts"]
    assert maps[0].has_contents
    assert maps[0].size == len(body.encode())
    assert maps[0].secrets == ["Stripe secret key x1"]
    assert client.requests == ["https://t:443/", "https://t:443/app.js"]
    finding = SourceMapExposurePlugin()._build_finding(maps, 443)
    assert finding.severity.value == "high"
    assert "Inline source map in https://t:443/app.js" in finding.evidence
    assert "data:" not in finding.evidence
    assert secret not in finding.evidence


@pytest.mark.parametrize("uri", [
    "data:application/json;base64,!!!", "data:application/json;base64,ey",
    "data:application/json;base64,/w==", "data:application/json,no-json",
    "data:application/json,%7B", "data:application/json;base64",
])
def test_invalid_inline_maps_fall_back_to_external_map(monkeypatch, uri):
    client = MapClient("//# sourceMappingURL=" + uri, '{"sources":["fallback.ts"]}')
    maps = collect(monkeypatch, client)
    assert len(maps) == 1
    assert maps[0].sources == ["fallback.ts"]
    assert not maps[0].inline
    assert client.requests == ["https://t:443/", "https://t:443/app.js", "https://t:443/app.js.map"]


@pytest.mark.parametrize("encoding", ["base64", "percent"])
def test_inline_decode_enforces_decoded_size_limit(monkeypatch, encoding):
    monkeypatch.setattr(module, "_MAX_MAP_BYTES", 32)
    def uri(body):
        if encoding == "base64":
            return "data:application/json;base64," + base64.b64encode(body).decode()
        return "data:application/json," + "".join(f"%{b:02X}" for b in body)
    assert decode_inline_map(uri(b"x" * 32)) == "x" * 32
    assert decode_inline_map(uri(b"x" * 33)) is None
    assert decode_inline_map(uri(b"x" * 100)) is None


def test_oversized_script_still_tries_conventional_external_map(monkeypatch):
    script = '//# sourceMappingURL=data:application/json,%7B%22sources%22:%5B%22a%22%5D%7D'
    monkeypatch.setattr(module, "_MAX_SCRIPT_BYTES", len(script.encode()) - 1)
    client = MapClient(script, '{"sources":["fallback.ts"]}')
    maps = collect(monkeypatch, client)
    assert len(maps) == 1
    assert maps[0].sources == ["fallback.ts"]
    assert not maps[0].inline
    assert client.requests == ["https://t:443/", "https://t:443/app.js", "https://t:443/app.js.map"]
