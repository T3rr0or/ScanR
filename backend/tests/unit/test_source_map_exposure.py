"""JavaScript source map exposure.

Pins the same-origin script extraction, map-candidate derivation, source-map
parsing (only a JSON object with a sources array counts) and the secret scan.
"""
from __future__ import annotations

from scanr.plugins.web.source_map_exposure import (
    SourceMap,
    SourceMapExposurePlugin,
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


def test_inline_data_map_points_back_at_the_bundle():
    cands = map_candidates("https://t/app.js", "//# sourceMappingURL=data:application/json;base64,eyj")
    assert cands[0] == "https://t/app.js"


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
