import asyncio

import httpcore
import pytest

from scanr.utils.safe_http import (
    PinnedTarget,
    UnsafeHTTPDestination,
    _PinnedNetworkBackend,
    resolve_pinned_target,
)


@pytest.mark.asyncio
async def test_resolution_rejects_mixed_safe_and_forbidden_answers(monkeypatch):
    loop = asyncio.get_running_loop()

    async def answers(*_args, **_kwargs):
        return [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]

    monkeypatch.setattr(loop, "getaddrinfo", answers)
    with pytest.raises(UnsafeHTTPDestination, match="forbidden DNS answer"):
        await resolve_pinned_target("https://example.test/hook")


@pytest.mark.asyncio
async def test_unresolvable_targets_fail_closed(monkeypatch):
    loop = asyncio.get_running_loop()

    async def no_answer(*_args, **_kwargs):
        raise OSError("no DNS")

    monkeypatch.setattr(loop, "getaddrinfo", no_answer)
    with pytest.raises(UnsafeHTTPDestination, match="did not resolve"):
        await resolve_pinned_target("https://missing.example/hook")


@pytest.mark.asyncio
async def test_private_answers_can_be_forbidden_at_the_pinned_boundary(monkeypatch):
    loop = asyncio.get_running_loop()

    async def private_answer(*_args, **_kwargs):
        return [(2, 1, 6, "", ("10.23.45.67", 443))]

    monkeypatch.setattr(loop, "getaddrinfo", private_answer)
    with pytest.raises(UnsafeHTTPDestination, match="private DNS answer"):
        await resolve_pinned_target(
            "https://hook.example.test/",
            forbid_private=True,
        )

    # Internal scan/integration targets remain supported when the caller's
    # policy deliberately allows them.
    target = await resolve_pinned_target("https://hook.example.test/")
    assert target.ip == "10.23.45.67"


@pytest.mark.asyncio
async def test_tcp_backend_uses_only_the_pinned_ip():
    target = PinnedTarget("example.test", "93.184.216.34", 443)
    backend = _PinnedNetworkBackend(target)
    calls = []

    class Delegate:
        async def connect_tcp(self, host, port, **kwargs):
            calls.append((host, port, kwargs))
            return object()

        async def sleep(self, _seconds):
            return None

    backend._backend = Delegate()
    await backend.connect_tcp("example.test", 443, timeout=2)
    assert calls[0][0:2] == ("93.184.216.34", 443)

    with pytest.raises(httpcore.ConnectError, match="unpinned"):
        await backend.connect_tcp("rebound.internal", 443)
    with pytest.raises(httpcore.ConnectError, match="unpinned"):
        await backend.connect_tcp("example.test", 8443)
