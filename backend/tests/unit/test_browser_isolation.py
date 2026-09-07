import base64
from urllib.parse import urlparse

import httpx
import pytest
from fastapi import HTTPException

from scanr import browser_service
from scanr.core import browser


def test_browser_service_token_fails_closed(monkeypatch):
    monkeypatch.setattr(browser_service, "_TOKEN", "")
    with pytest.raises(HTTPException) as exc:
        browser_service._check_token("anything")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_browser_service_rejects_denied_and_mixed_dns(monkeypatch):
    with pytest.raises(HTTPException) as exc:
        await browser_service._resolve_authorized("http://localhost/")
    assert exc.value.status_code == 403

    loop = __import__("asyncio").get_running_loop()

    async def mixed(*_args, **_kwargs):
        return [
            (2, 1, 6, "", ("93.184.216.34", 80)),
            (2, 1, 6, "", ("127.0.0.1", 80)),
        ]

    monkeypatch.setattr(loop, "getaddrinfo", mixed)
    with pytest.raises(HTTPException) as exc:
        await browser_service._resolve_authorized("http://example.test/")
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_sidecar_pins_the_authorized_dns_answer(monkeypatch):
    monkeypatch.setattr(browser_service, "_TOKEN", "x" * 32)
    monkeypatch.setattr(
        browser_service, "_resolve_authorized",
        lambda _url: _async_value(("example.test", "93.184.216.34")),
    )
    seen = {}

    async def fake_local(url, canary, **kwargs):
        seen.update(kwargs)
        return browser._empty_observation(url)

    monkeypatch.setattr(browser_service, "_observe_url_local", fake_local)
    result = await browser_service.observe(
        browser_service.ObserveRequest(url="https://example.test/path"),
        "x" * 32,
    )
    assert seen["pinned_host"] == ("example.test", "93.184.216.34")
    assert result["screenshot_b64"] is None


@pytest.mark.asyncio
async def test_worker_uses_sidecar_and_writes_bounded_screenshot(monkeypatch, tmp_path):
    png = b"\x89PNG\r\n\x1a\nsmall"

    class Response:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

        async def aiter_bytes(self):
            payload = {
                **browser._empty_observation("http://example.test/"),
                "status": 200,
                "title": "isolated",
                "screenshot_b64": base64.b64encode(png).decode(),
            }
            yield __import__("json").dumps(payload).encode()

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def stream(self, method, url, **kwargs):
            assert method == "POST"
            assert url == "http://browser:8091/observe"
            assert kwargs["headers"]["X-Browser-Token"] == "t" * 32
            return Response()

    monkeypatch.setenv("BROWSER_SERVICE_URL", "http://browser:8091")
    monkeypatch.setenv("BROWSER_SERVICE_TOKEN", "t" * 32)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    destination = tmp_path / "capture.png"
    result = await browser.observe_url(
        "http://example.test/", "canary", screenshot_path=str(destination)
    )
    assert result["status"] == 200
    assert result["title"] == "isolated"
    assert result["screenshot"] == str(destination)
    assert destination.read_bytes() == png


@pytest.mark.asyncio
async def test_worker_bounds_a_compromised_sidecar_response(monkeypatch):
    class Response:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def raise_for_status(self):
            return None

        async def aiter_bytes(self):
            chunk = b"x" * (browser.MAX_REMOTE_RESPONSE // 2 + 1)
            yield chunk
            yield chunk

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def stream(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setenv("BROWSER_SERVICE_URL", "http://browser:8091")
    monkeypatch.setenv("BROWSER_SERVICE_TOKEN", "t" * 32)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())

    result = await browser.observe_url("http://example.test/", "canary")
    assert "exceeded 8 MiB" in result["error"]


@pytest.mark.asyncio
async def test_production_requirement_never_falls_back_to_local(monkeypatch):
    monkeypatch.delenv("BROWSER_SERVICE_URL", raising=False)
    monkeypatch.setenv("SCANR_REQUIRE_BROWSER_SERVICE", "true")
    result = await browser.observe_url("http://example.test/", "canary")
    assert "required" in result["error"]


@pytest.mark.asyncio
async def test_browser_websockets_are_closed_before_connecting():
    """HTTP route handlers do not cover WebSockets, so they need their own gate."""
    closed = {}

    class WebSocket:
        async def close(self, **kwargs):
            closed.update(kwargs)

    await browser._block_web_socket(WebSocket())

    assert closed == {
        "code": 1008,
        "reason": "Blocked by ScanR origin policy",
    }


@pytest.mark.asyncio
async def test_browser_service_rejects_an_invalid_port():
    with pytest.raises(HTTPException) as exc:
        await browser_service._resolve_authorized("https://example.test:99999/")
    assert exc.value.status_code == 400


def test_sidecar_concurrency_reads_and_bounds_its_environment(monkeypatch):
    monkeypatch.setenv("BROWSER_VALIDATION_CONCURRENCY", "3")
    assert browser._configured_concurrency() == 3

    monkeypatch.setenv("BROWSER_VALIDATION_CONCURRENCY", "999999")
    assert browser._configured_concurrency() == browser.MAX_CONFIGURED_CONCURRENT

    monkeypatch.setenv("BROWSER_VALIDATION_CONCURRENCY", "not-an-int")
    assert browser._configured_concurrency() == browser.MAX_CONCURRENT


def test_browser_http_routes_require_the_exact_authorized_origin():
    allowed = urlparse("https://example.test:8443/start")

    assert browser._same_http_origin("https://example.test:8443/asset.js", allowed)
    assert not browser._same_http_origin("http://example.test:8443/", allowed)
    assert not browser._same_http_origin("https://other.test:8443/", allowed)
    assert not browser._same_http_origin("https://example.test:443/", allowed)
    assert not browser._same_http_origin("data:text/plain,hello", allowed)


async def _async_value(value):
    return value
