"""CMS identification and WordPress exposure enumeration."""
import json

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.web import cms_enum as ce


class _Ctx:
    def proxy_config(self):
        return {}

    def web_auth_headers(self):
        return {}


def _install(monkeypatch, handler):
    def factory(*_a, **_kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ce, "create_web_client", factory)


async def _run(seen=None):
    return await ce.CmsEnumPlugin()._scan(
        _Ctx(), "http://192.0.2.10:80", 80, seen if seen is not None else set()
    )


def _routes(pages: dict, default=404):
    """Serve `pages` by path; everything else gets `default`."""
    def handler(request):
        body = pages.get(request.url.path)
        if body is None:
            return httpx.Response(default, text="not found")
        if isinstance(body, tuple):
            status, text = body
            return httpx.Response(status, text=text)
        return httpx.Response(200, text=body)
    return handler


# ── identification ───────────────────────────────────────────────────────────

def test_identifies_from_the_generator_tag():
    body = '<meta name="generator" content="WordPress 6.4.2" />'
    assert ce.CmsEnumPlugin._identify(body) == "WordPress"
    assert ce.CmsEnumPlugin._version_from_body("WordPress", body) == "6.4.2"


@pytest.mark.parametrize("body,expected", [
    ('<link href="/wp-content/themes/x/style.css">', "WordPress"),
    ('<script src="/core/misc/drupal.js"></script>', "Drupal"),
    ('<link href="/media/jui/css/x.css">', "Joomla"),
    ("<html><body>plain site</body></html>", None),
])
def test_identifies_from_asset_paths(body, expected):
    assert ce.CmsEnumPlugin._identify(body) == expected


def test_version_absent_is_none():
    assert ce.CmsEnumPlugin._version_from_body("WordPress", "/wp-content/x") is None


# ── platform finding ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_version_disclosure_is_reported_as_low(monkeypatch):
    _install(monkeypatch, _routes({"/": '<meta name="generator" content="WordPress 5.8.1">'}))
    findings = await _run()
    platform = findings[0]
    assert platform.severity is Severity.low
    assert "5.8.1" in platform.title


@pytest.mark.asyncio
async def test_detection_without_a_version_is_informational(monkeypatch):
    _install(monkeypatch, _routes({"/": '<link href="/wp-includes/x.css">'}))
    findings = await _run()
    assert findings[0].severity is Severity.info
    assert findings[0].title == "WordPress Detected"


@pytest.mark.asyncio
async def test_non_cms_site_produces_nothing(monkeypatch):
    _install(monkeypatch, _routes({"/": "<html>just a site</html>"}))
    assert await _run() == []


@pytest.mark.asyncio
async def test_a_platform_is_only_reported_once_per_host(monkeypatch):
    _install(monkeypatch, _routes({"/": '<meta name="generator" content="Drupal 9">'}))
    seen = set()
    first = await _run(seen)
    second = await _run(seen)
    assert first and second == []


# ── WordPress specifics ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reports_rest_api_user_enumeration(monkeypatch):
    users = json.dumps([
        {"id": 1, "name": "Site Admin", "slug": "admin"},
        {"id": 2, "name": "Editor", "slug": "editor"},
    ])
    _install(monkeypatch, _routes({
        "/": '<link href="/wp-content/x.css">',
        "/wp-json/wp/v2/users": users,
    }))
    findings = await _run()
    enum = [f for f in findings if "User Enumeration" in f.title]
    assert len(enum) == 1
    assert enum[0].severity is Severity.medium
    assert "admin" in enum[0].evidence and "editor" in enum[0].evidence


@pytest.mark.asyncio
async def test_locked_down_users_endpoint_is_not_reported(monkeypatch):
    _install(monkeypatch, _routes({
        "/": '<link href="/wp-content/x.css">',
        "/wp-json/wp/v2/users": (401, '{"code":"rest_forbidden"}'),
    }))
    findings = await _run()
    assert not [f for f in findings if "User Enumeration" in f.title]


@pytest.mark.asyncio
async def test_non_list_users_payload_is_not_reported(monkeypatch):
    """An error object returned with HTTP 200 must not read as a user list."""
    _install(monkeypatch, _routes({
        "/": '<link href="/wp-content/x.css">',
        "/wp-json/wp/v2/users": '{"code":"rest_cannot_access"}',
    }))
    findings = await _run()
    assert not [f for f in findings if "User Enumeration" in f.title]


@pytest.mark.asyncio
async def test_reports_enabled_xmlrpc(monkeypatch):
    _install(monkeypatch, _routes({
        "/": '<link href="/wp-content/x.css">',
        "/xmlrpc.php": "<methodResponse><params/></methodResponse>",
    }))
    findings = await _run()
    xmlrpc = [f for f in findings if "xmlrpc" in f.title]
    assert len(xmlrpc) == 1
    assert xmlrpc[0].severity is Severity.medium


@pytest.mark.asyncio
async def test_disabled_xmlrpc_is_not_reported(monkeypatch):
    _install(monkeypatch, _routes({
        "/": '<link href="/wp-content/x.css">',
        "/xmlrpc.php": (403, "Forbidden"),
    }))
    findings = await _run()
    assert not [f for f in findings if "xmlrpc" in f.title]


@pytest.mark.asyncio
async def test_reports_readable_sensitive_paths(monkeypatch):
    _install(monkeypatch, _routes({
        "/": '<link href="/wp-content/x.css">',
        "/readme.html": "<h1>WordPress</h1>",
        "/wp-content/debug.log": "PHP Notice: ...",
    }))
    findings = await _run()
    paths = [f for f in findings if "Sensitive Paths" in f.title]
    assert len(paths) == 1
    assert "readme.html" in paths[0].evidence
    assert "debug.log" in paths[0].evidence


@pytest.mark.asyncio
async def test_directory_without_a_listing_is_not_reported(monkeypatch):
    """A 200 that is the site's own 404 page is not a directory listing."""
    _install(monkeypatch, _routes({
        "/": '<link href="/wp-content/x.css">',
        "/wp-content/uploads/": "<html>Nothing here</html>",
    }))
    findings = await _run()
    assert not [f for f in findings if "Sensitive Paths" in f.title]


@pytest.mark.asyncio
async def test_drupal_does_not_run_wordpress_probes(monkeypatch):
    asked: list[str] = []

    def handler(request):
        asked.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(200, text='<meta name="generator" content="Drupal 10">')
        return httpx.Response(404, text="")

    _install(monkeypatch, handler)
    await _run()
    assert not any("wp-json" in p or "xmlrpc" in p for p in asked)


@pytest.mark.asyncio
async def test_unreachable_host_produces_nothing(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")

    _install(monkeypatch, handler)
    assert await _run() == []


def test_plugin_sends_no_attack_payloads():
    """Every probe is a plain GET/POST of a documented path."""
    assert ce.CmsEnumPlugin.intrusive is False
    assert ce.CmsEnumPlugin.destructive is False
