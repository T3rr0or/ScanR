from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.web import http_methods


class _Response:
    def __init__(self, status_code: int = 204, headers: dict | None = None):
        self.status_code = status_code
        self.headers = headers or {}


class _Client:
    def __init__(self):
        self.requests: list[tuple[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def options(self, url):
        self.requests.append(("OPTIONS", url))
        return _Response(headers={})

    async def get(self, url):
        self.requests.append(("GET", url))
        return _Response(status_code=404)

    async def request(self, method, url):
        self.requests.append((method, url))
        return _Response()


@pytest.mark.asyncio
@pytest.mark.parametrize("safety_level", ["safe", "balanced"])
async def test_non_aggressive_http_method_probe_never_sends_mutating_verbs(
    monkeypatch, safety_level,
):
    client = _Client()
    monkeypatch.setattr(http_methods.httpx, "AsyncClient", lambda **_kwargs: client)
    context = SimpleNamespace(
        profile_json=lambda: {"safety_level": safety_level},
        proxy_config=lambda: {},
    )

    await http_methods.HttpMethodsPlugin()._probe_methods(context, "https://example.test/")

    sent = {method for method, _url in client.requests}
    assert not (sent & http_methods.STATE_CHANGING_METHODS)


@pytest.mark.asyncio
async def test_aggressive_mutating_probes_use_random_canary_path(monkeypatch):
    client = _Client()
    monkeypatch.setattr(http_methods.httpx, "AsyncClient", lambda **_kwargs: client)
    context = SimpleNamespace(
        profile_json=lambda: {"safety_level": "aggressive"},
        proxy_config=lambda: {},
    )

    await http_methods.HttpMethodsPlugin()._probe_methods(context, "https://example.test/")

    mutating = [
        (method, url) for method, url in client.requests
        if method in http_methods.STATE_CHANGING_METHODS
    ]
    assert {method for method, _url in mutating} == http_methods.STATE_CHANGING_METHODS
    assert all(url.startswith("https://example.test/") and url != "https://example.test/" for _, url in mutating)

