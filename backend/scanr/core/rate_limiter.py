from __future__ import annotations

import asyncio
from collections import defaultdict


class RateLimiter:
    """Per-target token-bucket rate limiter for concurrent plugin execution."""

    def __init__(self, max_concurrent_hosts: int = 50, max_concurrent_plugins: int = 20):
        self._host_semaphore = asyncio.Semaphore(max_concurrent_hosts)
        self._plugin_semaphores: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(max_concurrent_plugins)
        )

    async def acquire_host(self):
        return await self._host_semaphore.acquire()

    def release_host(self):
        self._host_semaphore.release()

    def host_slot(self):
        return self._host_semaphore

    def plugin_slot(self, host_ip: str):
        return self._plugin_semaphores[host_ip]
