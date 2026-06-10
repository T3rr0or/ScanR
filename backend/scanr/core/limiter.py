from __future__ import annotations

import ipaddress
from functools import lru_cache

from fastapi import Request
from slowapi import Limiter

from scanr.config import get_settings


@lru_cache
def _trusted_networks() -> tuple[ipaddress._BaseNetwork, ...]:
    nets: list[ipaddress._BaseNetwork] = []
    for entry in get_settings().trusted_proxy_list:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _peer_is_trusted(peer: str | None) -> bool:
    if not peer or not _trusted_networks():
        return False
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(addr in net for net in _trusted_networks())


def _real_ip(request: Request) -> str:
    """Return the client IP for rate limiting.

    X-Forwarded-For is honoured only when the direct TCP peer is a configured
    trusted proxy. Otherwise the header is ignored so a client cannot spoof its
    source IP to evade rate limits.
    """
    peer = request.client.host if request.client else None
    if _peer_is_trusted(peer):
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the leftmost (original client) IP; proxies append right-to-left
            return forwarded_for.split(",")[0].strip()
    return peer or "unknown"


limiter = Limiter(key_func=_real_ip, default_limits=["300/minute"])
