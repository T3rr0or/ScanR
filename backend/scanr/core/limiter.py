from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache

from fastapi import Request
from slowapi import Limiter

from scanr.config import get_settings

logger = logging.getLogger(__name__)


@lru_cache
def _trusted_networks() -> tuple[ipaddress._BaseNetwork, ...]:
    nets: list[ipaddress._BaseNetwork] = []
    for entry in get_settings().trusted_proxy_list:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("Ignoring unparseable TRUSTED_PROXIES entry: %r", entry)
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


# One-shot flag so the misconfiguration warning below doesn't fire per request.
_warned_untrusted_xff = False


def _warn_untrusted_xff_once(peer: str | None) -> None:
    """Surface the case where every client shares one rate-limit bucket.

    If requests arrive with X-Forwarded-For but the peer is not a configured
    trusted proxy, the header is deliberately ignored (it would otherwise be
    trivially spoofable) — which means every client is keyed by the proxy's IP.
    Login limits then apply globally: one client can exhaust the limit for
    everyone. That is a deployment error rather than something request handling
    can fix, so say so loudly once instead of degrading silently.
    """
    global _warned_untrusted_xff
    if _warned_untrusted_xff:
        return
    _warned_untrusted_xff = True
    logger.warning(
        "Requests carry X-Forwarded-For but the peer %s is not in TRUSTED_PROXIES, so "
        "the header is being ignored and ALL clients share one rate-limit bucket "
        "(a single client can exhaust the login limit for everyone). Set "
        "TRUSTED_PROXIES to your reverse proxy's address/CIDR — for the bundled "
        "docker-compose deployment that is the Docker network, e.g. 172.16.0.0/12.",
        peer,
    )


def _real_ip(request: Request) -> str:
    """Return the client IP for rate limiting.

    X-Forwarded-For is honoured only when the direct TCP peer is a configured
    trusted proxy. Otherwise the header is ignored so a client cannot spoof its
    source IP to evade rate limits.
    """
    peer = request.client.host if request.client else None
    forwarded_for = request.headers.get("X-Forwarded-For")
    if _peer_is_trusted(peer):
        if forwarded_for:
            # Take the leftmost (original client) IP; proxies append right-to-left
            return forwarded_for.split(",")[0].strip()
    elif forwarded_for:
        _warn_untrusted_xff_once(peer)
    return peer or "unknown"


# Back rate-limit counters with Redis so limits are shared across processes.
# slowapi's default in-memory storage is per-process and lost on restart: with
# more than one uvicorn worker or replica a '10/minute' login limit silently
# becomes 10/minute *per process*, and every restart clears the counters. Redis is
# already a hard dependency. Storage construction is lazy, so an unreachable
# Redis does not break import or startup.
limiter = Limiter(
    key_func=_real_ip,
    default_limits=["300/minute"],
    storage_uri=get_settings().redis_url,
)
