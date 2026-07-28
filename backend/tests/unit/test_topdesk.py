"""TOPdesk integration: payload mapping, URL policy, and the client's behaviour
against a mocked instance.

There is no TOPdesk to test against, so the wire contract is exercised through
httpx's MockTransport: what we send, how we read the reply, and — most
importantly — that we adopt an existing incident instead of opening a second one.
"""
import json
import types

import httpx
import pytest

from scanr.integrations.topdesk import (
    TopdeskClient,
    TopdeskConfig,
    TopdeskError,
    build_external_number,
    build_incident,
    validate_url,
)


def finding(**kw):
    base = dict(
        id="f-1", title="Anonymous FTP login allowed", severity="high",
        plugin_id="services.ftp_anon", port_number=21, cvss_score=7.5,
        description="The FTP service permits anonymous login.",
        evidence="230 Login successful.", remediation="Disable anonymous FTP.",
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def config(**kw):
    base = dict(url="https://example.topdesk.net", username="scanr",
                password="app-password", defaults={})
    base.update(kw)
    return TopdeskConfig(**base)


# ── URL policy ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://example.topdesk.net",
    "http://topdesk.corp.internal/tas",
    "https://10.1.2.3",       # on-prem over RFC1918 is the normal case
    "https://192.168.4.5:8443",
])
def test_reachable_urls_are_accepted(url):
    assert validate_url(url) == url.rstrip("/")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/tas",
    "https://169.254.169.254",     # cloud metadata
    "http://localhost:8080",
    "https://[::1]/tas",
])
def test_infrastructure_urls_are_refused(url):
    with pytest.raises(TopdeskError, match="loopback|infrastructure|hostname"):
        validate_url(url)


@pytest.mark.parametrize("url", ["ftp://x", "file:///etc/passwd", "not-a-url", ""])
def test_non_http_urls_are_refused(url):
    with pytest.raises(TopdeskError):
        validate_url(url)


def test_trailing_slash_is_normalised():
    assert validate_url("https://example.topdesk.net/") == "https://example.topdesk.net"


# ── payload mapping ──────────────────────────────────────────────────────────

def test_incident_carries_the_dedup_stamp():
    inc = build_incident(finding(), "192.0.2.10", "abc123", {})
    assert inc["externalNumber"] == build_external_number("abc123") == "scanr:abc123"


def test_brief_description_is_capped():
    """TOPdesk truncates briefDescription; do it here so the value we send is the
    value that lands."""
    inc = build_incident(finding(title="x" * 300), "192.0.2.10", "fp", {})
    assert len(inc["briefDescription"]) <= 80


def test_body_carries_the_detail_a_service_desk_needs():
    inc = build_incident(finding(), "192.0.2.10", "fp", {})
    body = inc["request"]
    for expected in ("192.0.2.10:21", "services.ftp_anon", "CVSS: 7.5",
                     "230 Login successful", "Disable anonymous FTP", "f-1"):
        assert expected in body, expected


def test_sparse_finding_still_maps():
    inc = build_incident(
        finding(port_number=None, cvss_score=None, description=None,
                evidence=None, remediation=None),
        "", "fp", {},
    )
    assert inc["briefDescription"]
    assert "unknown" in inc["request"]


@pytest.mark.parametrize("severity,priority", [
    ("critical", "P1"), ("high", "P2"), ("medium", "P3"), ("low", "P4"), ("info", "P4"),
])
def test_severity_maps_to_priority(severity, priority):
    inc = build_incident(finding(severity=severity), "192.0.2.10", "fp", {})
    assert inc["priority"] == {"name": priority}


def test_priority_mapping_is_overridable():
    """An instance with a customised priority scheme configures it rather than
    receiving our guess."""
    inc = build_incident(finding(severity="high"), "192.0.2.10", "fp",
                         {"priority_by_severity": {"high": "Urgent"}})
    assert inc["priority"] == {"name": "Urgent"}


def test_instance_specific_fields_are_only_set_when_configured():
    """Guessing at a customer's taxonomy produces incidents they must re-file."""
    bare = build_incident(finding(), "192.0.2.10", "fp", {})
    for field in ("category", "subcategory", "callType", "entryType",
                  "operatorGroup", "callerLookup", "status"):
        assert field not in bare, field

    full = build_incident(finding(), "192.0.2.10", "fp", {
        "category": "Security", "subcategory": "Vulnerability",
        "call_type": "Incident", "entry_type": "Automation",
        "operator_group": "SecOps", "caller_email": "sec@example.com",
        "status": "secondLine",
    })
    assert full["category"] == {"name": "Security"}
    assert full["operatorGroup"] == {"name": "SecOps"}
    assert full["callerLookup"]["email"] == "sec@example.com"
    assert full["status"] == "secondLine"


def test_invalid_status_is_dropped_rather_than_sent():
    inc = build_incident(finding(), "192.0.2.10", "fp", {"status": "nonsense"})
    assert "status" not in inc


# ── client ───────────────────────────────────────────────────────────────────

def _client(handler, **cfg):
    return TopdeskClient(config(**cfg), transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_create_sends_basic_auth_and_json():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(201, json={"id": "inc-1", "number": "I 2403 001"})

    out = await _client(handler).create_incident({"briefDescription": "x"})
    assert out["number"] == "I 2403 001"
    assert seen["auth"].startswith("Basic ")
    import base64
    assert base64.b64decode(seen["auth"].split()[1]).decode() == "scanr:app-password"
    assert seen["url"] == "https://example.topdesk.net/tas/api/incidents"


@pytest.mark.asyncio
async def test_search_by_external_number_finds_an_existing_incident():
    def handler(request: httpx.Request) -> httpx.Response:
        # httpx percent-encodes the query; compare the decoded parameter.
        assert request.url.params["query"] == "externalNumber==scanr:fp"
        return httpx.Response(200, json=[{"id": "inc-9", "number": "I 1"}])

    found = await _client(handler).find_by_external_number("scanr:fp")
    assert found["id"] == "inc-9"


@pytest.mark.asyncio
async def test_search_returning_nothing_is_none():
    handler = lambda r: httpx.Response(200, json=[])  # noqa: E731
    assert await _client(handler).find_by_external_number("scanr:fp") is None


@pytest.mark.asyncio
async def test_bad_credentials_give_an_actionable_message():
    handler = lambda r: httpx.Response(401, text="nope")  # noqa: E731
    with pytest.raises(TopdeskError, match="rejected the credentials"):
        await _client(handler).verify()


@pytest.mark.asyncio
async def test_404_points_at_the_url_rather_than_the_credentials():
    """The overwhelmingly common setup mistake is pasting a deep link instead of
    the instance base."""
    handler = lambda r: httpx.Response(404, text="")  # noqa: E731
    with pytest.raises(TopdeskError, match="check the instance URL"):
        await _client(handler).verify()


@pytest.mark.asyncio
async def test_network_failure_is_wrapped():
    def handler(request):
        raise httpx.ConnectError("no route to host")

    with pytest.raises(TopdeskError, match="Could not reach TOPdesk"):
        await _client(handler).verify()


@pytest.mark.asyncio
async def test_server_error_includes_the_status():
    handler = lambda r: httpx.Response(500, text="boom")  # noqa: E731
    with pytest.raises(TopdeskError, match="TOPdesk error 500"):
        await _client(handler).verify()


@pytest.mark.asyncio
async def test_non_json_create_response_is_reported():
    handler = lambda r: httpx.Response(201, text="<html>gateway</html>")  # noqa: E731
    with pytest.raises(TopdeskError, match="non-JSON"):
        await _client(handler).create_incident({})


@pytest.mark.asyncio
async def test_redirects_are_not_followed():
    """A redirect would re-send the Authorization header to wherever it points."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})

    with pytest.raises(TopdeskError, match="redirected"):
        await _client(handler).verify()


def test_incident_url_is_built_from_the_configured_base():
    url = _client(lambda r: httpx.Response(200)).incident_url("inc-1")
    assert url.startswith("https://example.topdesk.net/")
    assert "inc-1" in url


def test_incident_url_is_none_without_an_id():
    assert _client(lambda r: httpx.Response(200)).incident_url(None) is None


@pytest.mark.asyncio
async def test_redirect_message_names_the_destination():
    """So the operator can paste the right URL rather than guess."""
    def handler(request):
        return httpx.Response(301, headers={"location": "https://example.topdesk.net/tas/"})

    with pytest.raises(TopdeskError, match="https://example.topdesk.net/tas/"):
        await _client(handler).verify()
