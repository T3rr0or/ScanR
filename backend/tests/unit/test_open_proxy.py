"""Open forward proxy detection (TCP 3128, 8080, 8888, 1080).

Pins the HTTP-proxy classifier's key distinction: a proxy that *attempted* to
relay our canary request (502/503/504, or a body describing a resolution
failure) is reported, while a proxy that *refused* the request outright
(403/407/400/401/405 — rejected before it ever looked at the URL) must never
be reported, or every access-controlled proxy on the internet would fire.
Also ensures generic gateway errors do not get mistaken for forward-proxy
relay attempts and pins the SOCKS5 no-auth greeting check.
"""
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services.open_proxy import (
    OpenProxyPlugin,
    _looks_like_relay_attempt,
    _parse_http_status,
    _socks5_no_auth,
)


def _port(number, state="open"):
    return SimpleNamespace(number=number, state=state, banner=None, service=None)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


def _http(status: int, reason: str = "", body: str = "") -> bytes:
    return f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\n\r\n{body}".encode()


# ── status / body parsing ────────────────────────────────────────────────────

def test_parses_status_line():
    assert _parse_http_status(_http(502, "Bad Gateway")) == 502
    assert _parse_http_status(_http(403, "Forbidden")) == 403


@pytest.mark.parametrize("raw", [
    None,
    b"",
    b"\x05\x00",                              # SOCKS reply, not HTTP
    b"not even close to an http response",
])
def test_non_http_reply_has_no_status(raw):
    assert _parse_http_status(raw) is None


def test_relay_attempt_markers_are_case_insensitive():
    assert _looks_like_relay_attempt(b"502 Bad Gateway: Unable to resolve host") is True
    assert _looks_like_relay_attempt(b"DNS lookup failed for scanr-open-proxy-check.invalid") is True
    assert _looks_like_relay_attempt(b"200 OK: welcome to our website") is False


def test_socks5_no_auth_selection():
    assert _socks5_no_auth(b"\x05\x00") is True


@pytest.mark.parametrize("raw", [
    None,
    b"",
    b"\x05",                        # truncated
    b"\x05\xff",                    # no acceptable methods — refused
    b"\x04\x00",                    # SOCKS4, not 5
    b"HTTP/1.1 200 OK\r\n\r\n",     # not SOCKS at all
])
def test_socks5_refusal_or_garbage_is_not_open(raw):
    assert _socks5_no_auth(raw) is False


# ── plugin behaviour ─────────────────────────────────────────────────────────

def _patch_probes(monkeypatch, http_result=None, http_exc=None, socks_result=None, socks_exc=None):
    async def fake_http(self, ip, port):
        if http_exc is not None:
            raise http_exc
        return http_result

    async def fake_socks(self, ip, port):
        if socks_exc is not None:
            raise socks_exc
        return socks_result

    monkeypatch.setattr(OpenProxyPlugin, "_probe_http", fake_http)
    monkeypatch.setattr(OpenProxyPlugin, "_probe_socks", fake_socks)


@pytest.mark.asyncio
async def test_http_proxy_that_attempted_the_relay_is_reported(monkeypatch):
    """An explicit DNS failure for our canary shows the proxy tried to relay."""
    _patch_probes(monkeypatch, http_result=_http(502, "Bad Gateway", "Unable to resolve host"))
    host = _host([_port(3128)])

    findings = await OpenProxyPlugin().check(None, host)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.title == "Open HTTP Forward Proxy"
    assert "502" in finding.evidence
    assert finding.port_number == 3128
    assert finding.protocol == "tcp"


@pytest.mark.asyncio
async def test_relay_attempt_detected_from_body_marker_alone(monkeypatch):
    """Some proxies answer 200 with an HTML error page describing the DNS failure."""
    _patch_probes(monkeypatch, http_result=_http(200, "OK", "Error: could not resolve hostname"))
    host = _host([_port(8080)])

    findings = await OpenProxyPlugin().check(None, host)
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_proxy_that_refuses_the_request_is_never_reported(monkeypatch):
    """403/407/400 mean the proxy rejected us before it ever tried the URL —
    this is the critical guard: without it, every access-controlled proxy on
    the internet would be reported as open."""
    _patch_probes(monkeypatch, http_result=_http(403, "Forbidden"), socks_result=None)
    host = _host([_port(3128)])

    assert await OpenProxyPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_refusal_short_circuits_even_if_body_contains_relay_wording(monkeypatch):
    """A refusal page that happens to mention 'gateway' must still not count —
    the status code decides first."""
    _patch_probes(
        monkeypatch,
        http_result=_http(407, "Proxy Authentication Required", "Access via this gateway denied"),
    )
    host = _host([_port(3128)])

    assert await OpenProxyPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_plain_web_server_answering_for_itself_is_not_a_proxy(monkeypatch):
    """200/404 for the absolute-form request means a normal web server treated
    it as a path on itself — not a proxy — and the SOCKS probe also finds
    nothing, so there is no finding at all."""
    _patch_probes(
        monkeypatch,
        http_result=_http(404, "Not Found", "no such page"),
        socks_result=None,
    )
    host = _host([_port(8080)])

    assert await OpenProxyPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_open_socks5_proxy_is_reported(monkeypatch):
    _patch_probes(monkeypatch, http_result=None, socks_result=b"\x05\x00")
    host = _host([_port(1080)])

    findings = await OpenProxyPlugin().check(None, host)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.title == "Open SOCKS5 Forward Proxy"
    assert "05 00" in finding.evidence
    assert finding.port_number == 1080


@pytest.mark.asyncio
async def test_socks5_server_requiring_auth_is_not_reported(monkeypatch):
    _patch_probes(monkeypatch, http_result=None, socks_result=b"\x05\xff")
    host = _host([_port(1080)])

    assert await OpenProxyPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_http_finding_takes_priority_over_socks_probe(monkeypatch):
    """Once the HTTP probe already proves an open proxy, the SOCKS probe result
    (even garbage) must not change or duplicate the outcome."""
    _patch_probes(
        monkeypatch,
        http_result=_http(504, "Gateway Timeout", "DNS lookup failed for canary"),
        socks_result=b"garbage-not-socks",
    )
    host = _host([_port(3128)])

    findings = await OpenProxyPlugin().check(None, host)
    assert len(findings) == 1
    assert findings[0].title == "Open HTTP Forward Proxy"


@pytest.mark.parametrize("status", [502, 503, 504])
@pytest.mark.asyncio
async def test_generic_gateway_error_is_not_proof_of_forward_proxy(monkeypatch, status):
    _patch_probes(
        monkeypatch,
        http_result=_http(status, "Gateway Error", "upstream application unavailable"),
        socks_result=None,
    )
    assert await OpenProxyPlugin().check(None, _host([_port(8080)])) == []


@pytest.mark.asyncio
async def test_closed_port_is_skipped_without_probing(monkeypatch):
    async def fail_if_called(self, ip, port):
        raise AssertionError("must not probe a closed port")
    monkeypatch.setattr(OpenProxyPlugin, "_probe_http", fail_if_called)
    monkeypatch.setattr(OpenProxyPlugin, "_probe_socks", fail_if_called)
    host = _host([_port(3128, state="closed")])

    assert await OpenProxyPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_unreachable_port_produces_no_finding_and_no_exception(monkeypatch):
    _patch_probes(monkeypatch, http_exc=ConnectionRefusedError())
    host = _host([_port(3128)])

    assert await OpenProxyPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_wrong_protocol_replies_produce_no_finding(monkeypatch):
    """Neither reply looks like HTTP nor SOCKS5 — some unrelated service is
    listening on this port and must not be reported as a proxy."""
    _patch_probes(
        monkeypatch,
        http_result=b"SSH-2.0-OpenSSH_9.6\r\n",
        socks_result=b"SSH-2.0-OpenSSH_9.6\r\n",
    )
    host = _host([_port(8888)])

    assert await OpenProxyPlugin().check(None, host) == []
