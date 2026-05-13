"""ScanLogger — structured event emitter for live scan progress.

Engine and plugins call `ctx.log(...)` which publishes a JSON event to the
Redis pub/sub channel ``scanr:events:{scan_id}``.  The WebSocket endpoint
subscribes to that channel and fans out to connected browsers.

Event schema:
  {
    "type": "log",
    "scan_id": "...",
    "ts": "2026-04-13T18:00:00Z",     # ISO-8601
    "level": "info"|"warn"|"error"|"debug"|"finding",
    "phase": "discovery"|"portscan"|"fingerprint"|"plugin"|"engine",
    "msg": "...",
    "meta": {...}                       # optional extra fields
  }
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


class ScanLogger:
    """Attached to ScanContext — emits events to Redis pub/sub."""

    CHANNEL_PREFIX = "scanr:events:"

    def __init__(self, scan_id: str, debug: bool = False):
        self.scan_id = scan_id
        self._channel = f"{self.CHANNEL_PREFIX}{scan_id}"
        self._redis: "redis.asyncio.Redis | None" = None  # lazy init
        self._debug = debug  # gate debug events over WS

    async def _get_redis(self):
        if self._redis is None:
            # Fork-safe: create a fresh connection per worker process.
            # The shared pool (scanr.db.redis) is created in the API process
            # and doesn't survive Celery's prefork worker model.
            import redis.asyncio as aioredis
            from scanr.config import get_settings
            self._redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        return self._redis

    async def emit(
        self,
        msg: str,
        level: str = "info",
        phase: str = "engine",
        meta: dict | None = None,
    ) -> None:
        event = {
            "type": "log",
            "scan_id": self.scan_id,
            "ts": _now(),
            "level": level,
            "phase": phase,
            "msg": msg,
        }
        if meta:
            event["meta"] = meta
        # Always log locally too
        _py_level = {"warn": "warning", "finding": "info"}.get(level, level)
        log_fn = getattr(logger, _py_level if _py_level in ("debug", "info", "warning", "error") else "info")
        log_fn("[scan:%s] [%s] %s", self.scan_id[:8], phase, msg)
        try:
            r = await self._get_redis()
            payload = json.dumps(event)
            history_key = f"scanr:history:{self.scan_id}"
            async with r.pipeline() as pipe:
                await pipe.publish(self._channel, payload)
                await pipe.rpush(history_key, payload)
                await pipe.ltrim(history_key, -20_000, -1)  # keep last 20k events
                await pipe.expire(history_key, 60 * 60 * 24 * 14)  # 14-day TTL
                await pipe.execute()
        except Exception as exc:
            logger.debug("ScanLogger publish failed: %s", exc)

    # Convenience shorthands
    async def info(self, msg: str, phase: str = "engine", **meta) -> None:
        await self.emit(msg, "info", phase, meta or None)

    async def warn(self, msg: str, phase: str = "engine", **meta) -> None:
        await self.emit(msg, "warn", phase, meta or None)

    async def error(self, msg: str, phase: str = "engine", **meta) -> None:
        await self.emit(msg, "error", phase, meta or None)

    async def debug(self, msg: str, phase: str = "engine", **meta) -> None:
        # Always log locally; always emit over WS for command visibility
        logger.debug("[scan:%s] [%s] %s", self.scan_id[:8], phase, msg)
        await self.emit(msg, "debug", phase, meta or None)

    async def finding(self, title: str, severity: str, host: str, plugin: str, **meta) -> None:
        await self.emit(
            f"[{severity.upper()}] {title}",
            level="finding",
            phase="plugin",
            meta={"severity": severity, "host": host, "plugin": plugin, **meta},
        )

    async def phase_start(self, phase: str, msg: str, **meta) -> None:
        await self.emit(f"▶ {msg}", "info", phase, meta or None)

    async def phase_done(self, phase: str, msg: str, **meta) -> None:
        await self.emit(f"✓ {msg}", "info", phase, meta or None)

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()
            self._redis = None
