"""Proxy support for HTTP-based plugins.

All HTTP plugins can route through a proxy (Burp Suite, SOCKS5 pivot) for
interception and traffic routing in pentest engagements.

Set PROXY_URL in .env:  http://127.0.0.1:8080  or  socks5://pivot:1080
"""

from __future__ import annotations

import os
from typing import Any


def get_proxy_config() -> dict[str, Any]:
    """Return httpx proxy kwargs, or empty dict if no proxy configured."""
    url = (os.getenv("PROXY_URL") or "").strip()
    if not url:
        from scanr.config import get_settings
        url = get_settings().proxy_url.strip()
    if not url:
        return {}

    return {"proxy": url}


def get_proxy_mounts() -> dict[str, Any] | None:
    """Return httpx mounts dict for routing all traffic via proxy."""
    cfg = get_proxy_config()
    if not cfg:
        return None
    # httpx handles proxy routing natively via the 'proxy' kwarg,
    # so we return None here and use get_proxy_config() directly.
    return None
