"""Shared async Redis connection pool for ScanR.

Provides a module-level pool created at application startup (lifespan) so
every Redis call reuses connections instead of creating new ones per-request.
"""

from __future__ import annotations

import logging

import redis.asyncio as aioredis

from scanr.config import get_settings

logger = logging.getLogger(__name__)

_pool: aioredis.Redis | None = None


async def init_redis() -> None:
    """Create the shared Redis connection pool. Call once at startup."""
    global _pool
    settings = get_settings()
    _pool = aioredis.from_url(settings.redis_url, decode_responses=True)
    await _pool.ping()
    logger.info("Redis connection pool ready")


async def close_redis() -> None:
    """Close the shared Redis connection pool. Call at shutdown."""
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
        logger.info("Redis connection pool closed")


def get_redis() -> aioredis.Redis:
    """Return the shared async Redis client. Raises if not initialised."""
    if _pool is None:
        raise RuntimeError(
            "Redis pool not initialised. Call init_redis() during application startup."
        )
    return _pool
