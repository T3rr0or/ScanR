"""Regression tests for web/TLS plugin audit findings."""
from types import SimpleNamespace

import httpx
import pytest

from scanr.plugins.ssl_tls import poodle_beast
from scanr.plugins.web import api_key_exposure, ssrf_detect, spring4shell_check


def test_api_key_script_fetch_is_same_origin_only():
    base = "https://192.0.2.10:8443"
    assert api_key_exposure._same_origin(base, "/assets/app.js")
    assert api_key_exposure._same_origin(base, "https://192.0.2.10:8443/app.js")
    assert api_key_exposure._same_origin("https://192.0.2.10:443", "https://192.0.2.10/app.js")
    assert api_key_exposure._same_origin("https://192.0.2.10", "https://192.0.2.10:443/app.js")
    assert not api_key_exposure._same_origin(base, "https://cdn.example/app.js")
    assert not api_key_exposure._same_origin(base, "http://192.0.2.10:8443/app.js")
    assert not api_key_exposure._same_origin(base, "https://user@192.0.2.10:8443/app.js")


def test_publishable_stripe_key_is_not_reported_as_secret():
    hits = []
    api_key_exposure.ApiKeyExposurePlugin()._scan_content(
        'const key = "pk_live_123456789012345678901234";', "https://target/", hits
    )
    assert hits == []


@pytest.mark.asyncio
async def test_api_key_scanner_does_not_fetch_external_script(monkeypatch):
    requests = []
    real_client = httpx.AsyncClient

    def handler(request):
        requests.append(str(request.url))
        if request.url.path == "/":
            return httpx.Response(
                200,
                text=(
                    '<script src="https://outside.example/payload.js"></script>'
                    '<script src="/bundle.js"></script>'
                ),
            )
        if request.url.path == "/bundle.js":
            return httpx.Response(200, text='const aws = "AKIA1234567890ABCDEF";')
        return httpx.Response(404)

    monkeypatch.setattr(
        api_key_exposure.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    context = SimpleNamespace(proxy_config=lambda: {})
    finding = await api_key_exposure.ApiKeyExposurePlugin()._scan_for_keys(
        context, "https://target.example", 443
    )
    assert finding is not None
    assert "outside.example" not in " ".join(requests)
    assert any(url.endswith("/bundle.js") for url in requests)


@pytest.mark.asyncio
async def test_ssrf_length_delta_alone_does_not_report(monkeypatch):
    real_client = httpx.AsyncClient

    def handler(request):
        # Simulate ordinary reflection/branching: the response size changes a
        # lot for the internal URL, but no internal data was fetched.
        size = 900 if "127.0.0.1" in str(request.url) else 250
        return httpx.Response(200, text="x" * size)

    monkeypatch.setattr(
        ssrf_detect.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )

    async def no_crawl(_base, _client):
        return SimpleNamespace(paths=[], form_paths=[], get_params=[])

    monkeypatch.setattr(ssrf_detect, "crawl", no_crawl)
    context = SimpleNamespace(proxy_config=lambda: {})
    finding = await ssrf_detect.SsrfDetectPlugin()._test_ssrf(
        context, "http://target.example", 80
    )
    assert finding is None


class _CountingStream(httpx.AsyncByteStream):
    def __init__(self, size):
        self.size = size
        self.bytes_yielded = 0

    async def __aiter__(self):
        remaining = self.size
        chunk = b"J" * 8192
        while remaining:
            current = min(remaining, len(chunk))
            self.bytes_yielded += current
            yield chunk[:current]
            remaining -= current

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_heapdump_probe_stops_after_small_prefix():
    stream = _CountingStream(20 * 1024 * 1024)

    def handler(request):
        if request.url.path == "/actuator/env":
            return httpx.Response(404)
        return httpx.Response(
            200,
            headers={"content-type": "application/octet-stream", "content-length": str(stream.size)},
            stream=stream,
        )

    plugin = spring4shell_check.Spring4ShellCheckPlugin()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        findings = await plugin._check_actuator(client, "http://target", 8080)

    assert any("heapdump" in finding.title.lower() for finding in findings)
    assert stream.bytes_yielded <= 8192


def test_ssl3_probe_does_not_fall_back_to_tls10(monkeypatch):
    class Versions:
        TLSv1 = object()

    monkeypatch.setattr(poodle_beast.ssl, "TLSVersion", Versions)
    monkeypatch.setattr(
        poodle_beast.ssl, "SSLContext", lambda *_args: pytest.fail("must not create fallback TLS context")
    )
    assert not poodle_beast.PoodleBeastPlugin()._test_protocol("127.0.0.1", 443, "SSLv3")


def test_tls10_beast_probe_offers_only_cbc_suites(monkeypatch):
    seen_ciphers = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    class FakeContext:
        check_hostname = True
        verify_mode = None

        def set_ciphers(self, expression):
            seen_ciphers.append(expression)

        def wrap_socket(self, sock, server_hostname=None):
            return FakeSocket()

    monkeypatch.setattr(poodle_beast.ssl, "SSLContext", lambda *_args: FakeContext())
    monkeypatch.setattr(poodle_beast.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    assert poodle_beast.PoodleBeastPlugin()._test_protocol("127.0.0.1", 443, "TLSv1-CBC")
    assert seen_ciphers == ["AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:DES-CBC3-SHA"]
