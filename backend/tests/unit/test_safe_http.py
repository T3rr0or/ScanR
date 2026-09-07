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


# ── vhost fetches pinned to an already-authorized address ────────────────────


@pytest.mark.asyncio
async def test_client_pinned_to_ip_keeps_the_vhost_and_ignores_dns():
    """Web plugins address a target by hostname so name-based vhosts answer.

    The engine already resolved and authorized the IP; re-resolving the name at
    connect time is the DNS-rebinding window this closes. The Host header and
    SNI must still carry the hostname.
    """
    import http.server
    import socketserver
    import threading

    from scanr.utils.safe_http import client_pinned_to_ip

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = self.headers.get("Host", "").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        async with client_pinned_to_ip(
            "127.0.0.1", port, hostname="shop.example.test", timeout=5.0
        ) as client:
            resp = await client.get(f"http://shop.example.test:{port}/")
        assert resp.status_code == 200
        assert resp.text.startswith("shop.example.test")
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_client_pinned_to_ip_refuses_a_second_destination():
    from scanr.utils.safe_http import client_pinned_to_ip

    async with client_pinned_to_ip(
        "192.0.2.10", 80, hostname="target.test", timeout=1.0
    ) as client:
        with pytest.raises(Exception, match="unpinned"):
            await client.get("http://elsewhere.test/")


@pytest.mark.asyncio
async def test_pinning_is_skipped_when_an_egress_proxy_is_configured():
    """With a proxy the TCP peer is the proxy, so pinning the target would break it."""
    from scanr.utils.safe_http import client_pinned_to_ip

    client = client_pinned_to_ip(
        "192.0.2.10", 80,
        hostname="target.test",
        proxy_config={"proxy": "http://127.0.0.1:8080"},
    )
    async with client:
        assert client._mounts or client._transport is not None
