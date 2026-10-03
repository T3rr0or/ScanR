"""Periodic housekeeping in the API process."""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

_EVERY_SECONDS = 6 * 3600
_STARTUP_DELAY_SECONDS = 120


async def remove_orphaned_evidence() -> int:
    """Evidence rows disappear with their finding (ON DELETE CASCADE, including
    scan and user deletion); this removes the files they left on disk."""
    from sqlalchemy import select

    from scanr.core import evidence
    from scanr.db.session import AsyncSessionLocal
    from scanr.models.finding_attachment import FindingAttachment

    async with AsyncSessionLocal() as db:
        known = {row[0] for row in (await db.execute(select(FindingAttachment.id))).all()}
    return await asyncio.to_thread(evidence.remove_orphans, known)


async def maintenance_loop() -> None:
    await asyncio.sleep(_STARTUP_DELAY_SECONDS)
    while True:
        try:
            removed = await remove_orphaned_evidence()
            if removed:
                logger.info("Removed %d orphaned evidence files", removed)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Maintenance run failed")
        await asyncio.sleep(_EVERY_SECONDS)
