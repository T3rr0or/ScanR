"""Connection-bound HTTP target authorization.

String validation followed by a normal HTTP client has a DNS-rebinding gap: the
client resolves the hostname a second time.  This module resolves and validates
all answers once, then replaces only the TCP destination in httpcore.  The URL
hostname remains unchanged, preserving the HTTP Host header and TLS SNI.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import httpcore
import httpx

from scanr.utils.ip_utils import canonical_ip, is_forbidden_target


class UnsafeHTTPDestination(ValueError):
    """Raised before any network connection when an HTTP target is not allowed."""


@dataclass(frozen=True)
class PinnedTarget:
    hostname: str
    ip: str
    port: int


async def resolve_pinned_target(
    url: str,
    extra_denylist: set[str] | None = None,
    *,
    forbid_private: bool = False,
) -> PinnedTarget:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeHTTPDestination("only absolute HTTP(S) URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeHTTPDestination("URL userinfo is not allowed")
    hostname = parsed.hostname.rstrip(".").lower()
    if is_forbidden_target(hostname, extra_denylist):
        raise UnsafeHTTPDestination(f"HTTP target {hostname!r} is denied")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeHTTPDestination("invalid target port") from exc
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM
        )
    except (OSError, UnicodeError) as exc:
        raise UnsafeHTTPDestination(f"HTTP target {hostname!r} did not resolve") from exc

    answers = sorted({canonical_ip(str(info[4][0])) or str(info[4][0]) for info in infos})
    if not answers:
        raise UnsafeHTTPDestination(f"HTTP target {hostname!r} did not resolve")
    if any(is_forbidden_target(answer, extra_denylist) for answer in answers):
        raise UnsafeHTTPDestination(
            f"HTTP target {hostname!r} returned a forbidden DNS answer"
        )
    if forbid_private and any(ipaddress.ip_address(answer).is_private for answer in answers):
        raise UnsafeHTTPDestination(
            f"HTTP target {hostname!r} returned a private DNS answer"
        )
    return PinnedTarget(hostname=hostname, ip=answers[0], port=port)


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, target: PinnedTarget):
        self._target = target
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ) -> httpcore.AsyncNetworkStream:
        normalized = host.rstrip(".").lower()
        if normalized != self._target.hostname or port != self._target.port:
            raise httpcore.ConnectError(
                f"connection to unpinned destination {host}:{port} refused"
            )
        return await self._backend.connect_tcp(
            self._target.ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(self, path: str, timeout=None, socket_options=None):
        raise httpcore.ConnectError("Unix sockets are not allowed by the pinned HTTP transport")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


def client_pinned_to_ip(
    ip: str,
    port: int,
    *,
    hostname: str | None = None,
    timeout: float | httpx.Timeout = 10.0,
    verify: bool = False,
    headers: dict | None = None,
    proxy_config: dict | None = None,
    follow_redirects: bool = False,
    limits: httpx.Limits | None = None,
) -> httpx.AsyncClient:
    """Client for an address the scan already authorized, reached by vhost name.

    Plugins prefer a hostname over an IP so name-based virtual hosts serve their
    real application. An ordinary client resolves that name again at connect
    time, which reopens the DNS-rebinding window the engine closed when it
    resolved and validated the target once: a low-TTL record can point somewhere
    else entirely by the time a plugin runs. Pinning the TCP destination to the
    IP the engine authorized keeps the Host header and TLS SNI intact while
    making the second lookup irrelevant.

    When an egress proxy is configured the connection goes to the proxy rather
    than the target, so pinning is skipped — the proxy is the authorized path.
    """
    kwargs: dict = {
        "timeout": timeout,
        "follow_redirects": follow_redirects,
    }
    if headers:
        kwargs["headers"] = headers
    if limits is not None:
        kwargs["limits"] = limits

    if proxy_config:
        return httpx.AsyncClient(verify=verify, **proxy_config, **kwargs)

    transport = httpx.AsyncHTTPTransport(verify=verify, trust_env=False, retries=0)
    pool = getattr(transport, "_pool", None)
    if pool is None or not hasattr(pool, "_network_backend"):
        raise RuntimeError("httpx transport no longer exposes a pinnable network backend")
    authority = (hostname or ip).rstrip(".").lower()
    pool._network_backend = _PinnedNetworkBackend(
        PinnedTarget(hostname=authority, ip=ip, port=port)
    )
    return httpx.AsyncClient(transport=transport, trust_env=False, **kwargs)


async def pinned_async_client(
    url: str,
    *,
    extra_denylist: set[str] | None = None,
    timeout: float | httpx.Timeout = 10.0,
    verify: bool = True,
    forbid_private: bool = False,
) -> httpx.AsyncClient:
    """Return a client that can connect only to the URL's validated DNS answer.

    The project hash-locks httpx/httpcore.  We intentionally fail closed if their
    transport internals change instead of silently returning to ordinary DNS.
    """
    target = await resolve_pinned_target(
        url,
        extra_denylist,
        forbid_private=forbid_private,
    )
    transport = httpx.AsyncHTTPTransport(verify=verify, trust_env=False, retries=0)
    pool = getattr(transport, "_pool", None)
    if pool is None or not hasattr(pool, "_network_backend"):
        await transport.aclose()
        raise RuntimeError("httpx transport no longer exposes a pinnable network backend")
    pool._network_backend = _PinnedNetworkBackend(target)
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    )
