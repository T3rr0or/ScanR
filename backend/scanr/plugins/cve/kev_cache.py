"""TTL-cached access to the CISA KEV catalog id set.

``nvd_loader.get_kev_cve_ids()`` opens the local sqlite catalog and runs a full
SELECT on every call. The result collector used to call it per finding and the
CVE matcher per port — thousands of identical reads per scan. The catalog only
changes when the NVD feed is refreshed, so cache the id set for an hour and
share it across all callers.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time

logger = logging.getLogger(__name__)

_KEV_TTL_SECONDS = 3600

_cache: tuple[float, frozenset[str]] | None = None
_lock = threading.Lock()


def get_kev_cve_ids_cached() -> frozenset[str]:
    """Return the KEV id set, re-reading the sqlite catalog at most once per TTL."""
    global _cache
    now = time.monotonic()
    cached = _cache
    if cached is not None and now - cached[0] < _KEV_TTL_SECONDS:
        return cached[1]
    with _lock:
        # Double-checked: another thread may have refreshed while we waited.
        cached = _cache
        if cached is not None and now - cached[0] < _KEV_TTL_SECONDS:
            return cached[1]
        from scanr.plugins.cve.nvd_loader import get_kev_cve_ids
        ids = frozenset(get_kev_cve_ids())
        _cache = (now, ids)
        return ids


async def aget_kev_cve_ids() -> frozenset[str]:
    """Async variant — offloads a blocking cache-miss sqlite read to a thread."""
    return await asyncio.to_thread(get_kev_cve_ids_cached)
