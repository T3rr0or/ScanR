from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class HostRateState:
    consecutive_429s: int = 0
    backoff_until: float = 0.0  # monotonic timestamp
    gave_up: bool = False


class RateLimiter:
    """Per-target token-bucket rate limiter for concurrent plugin execution.

    Also tracks 429/503 responses per host and applies exponential backoff:
    2s → 4s → 8s → 16s → give up after 4 consecutive rate-limited responses.
    """

    def __init__(self, max_concurrent_hosts: int = 50, max_concurrent_plugins: int = 20):
        self._host_semaphore = asyncio.Semaphore(max_concurrent_hosts)
        self._plugin_semaphores: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(max_concurrent_plugins)
        )
        self._rate_state: dict[str, HostRateState] = {}

    async def acquire_host(self):
        return await self._host_semaphore.acquire()

    def release_host(self):
        self._host_semaphore.release()

    def host_slot(self):
        return self._host_semaphore

    def plugin_slot(self, host_ip: str):
        return self._plugin_semaphores[host_ip]

    def record_response(self, host_ip: str, status_code: int) -> None:
        """Call after every HTTP response to track rate-limit state."""
        state = self._rate_state.setdefault(host_ip, HostRateState())
        if status_code in (429, 503):
            state.consecutive_429s += 1
            delay = min(2 ** state.consecutive_429s, 16)  # 2,4,8,16
            state.backoff_until = time.monotonic() + delay
            if state.consecutive_429s >= 4:
                state.gave_up = True
        else:
            state.consecutive_429s = 0

    async def wait_if_throttled(self, host_ip: str) -> bool:
        """Wait out any backoff, return False if we should give up on this host."""
        state = self._rate_state.get(host_ip)
        if state is None:
            return True
        if state.gave_up:
            return False
        remaining = state.backoff_until - time.monotonic()
        if remaining > 0:
            await asyncio.sleep(remaining)
        return True
