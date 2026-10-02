"""Keep EPSS and CISA KEV current and the fix-first ranking in step with them.

Runs inside the API process, which is the only service with general outbound
network access in the bundled deployment. Both feeds publish once a day.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

from scanr.config import get_settings

logger = logging.getLogger(__name__)

_MAX_AGE_SECONDS = 20 * 3600
_CHECK_EVERY_SECONDS = 6 * 3600
_STARTUP_DELAY_SECONDS = 30


def _epss_age_seconds() -> float | None:
    from scanr.plugins.cve import epss

    fetched = epss.status().get("fetched_at")
    if not fetched:
        return None
    try:
        then = datetime.fromisoformat(str(fetched))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - then).total_seconds()


def _kev_age_seconds() -> float | None:
    from scanr.plugins.cve.nvd_loader import KEV_DB_PATH

    if not KEV_DB_PATH.exists():
        return None
    return time.time() - KEV_DB_PATH.stat().st_mtime


def refresh_feeds_if_stale() -> bool:
    """Download whichever feed is missing or older than ~a day. Blocking."""
    from scanr.plugins.cve import epss, kev_cache
    from scanr.plugins.cve.nvd_loader import download_cisa_kev

    changed = False
    age = _epss_age_seconds()
    if age is None or age > _MAX_AGE_SECONDS:
        try:
            epss.download_epss()
            changed = True
        except Exception as exc:
            logger.warning("EPSS refresh failed: %s", exc)
    age = _kev_age_seconds()
    if age is None or age > _MAX_AGE_SECONDS:
        download_cisa_kev()  # logs and swallows its own errors
        kev_cache.invalidate()
        changed = True
    return changed


async def refresh_once() -> int:
    """Refresh stale feeds, then re-score. Returns findings scored."""
    from scanr.core.priority_service import rescore
    from scanr.db.session import AsyncSessionLocal
    from scanr.models import Finding

    changed = await asyncio.to_thread(refresh_feeds_if_stale)
    async with AsyncSessionLocal() as db:
        if changed:
            return await rescore(db)
        # Nothing new, but findings from before this feature (or whose scoring
        # failed) still need a first score.
        return await rescore(db, Finding.priority_score.is_(None))


async def refresh_loop() -> None:
    if not get_settings().threat_feed_auto_refresh:
        logger.info("Automatic EPSS/KEV refresh disabled (THREAT_FEED_AUTO_REFRESH=false)")
        return
    await asyncio.sleep(_STARTUP_DELAY_SECONDS)
    while True:
        try:
            scored = await refresh_once()
            if scored:
                logger.info("Fix-first priority updated for %d findings", scored)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Threat feed refresh failed")
        await asyncio.sleep(_CHECK_EVERY_SECONDS)
