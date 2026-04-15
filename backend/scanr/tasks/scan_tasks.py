from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from .celery_app import celery_app

logger = logging.getLogger(__name__)


def _make_session():
    """Create a fresh async engine + session bound to the current event loop.

    Celery workers run each task in a new event loop.  The shared engine in
    session.py uses asyncpg's connection pool which is tied to the loop that
    created it — reusing it across loops causes 'Future attached to a
    different loop' errors.  NullPool skips pooling entirely so every call
    opens a fresh connection on whatever loop is active.
    """
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool
    from scanr.config import get_settings

    settings = get_settings()
    engine = create_async_engine(
        settings.database_url,
        poolclass=NullPool,
        connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
    )
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)


@celery_app.task(bind=True, name="scanr.run_scan")
def run_scan_task(self, scan_id: str) -> dict:
    """Celery task: orchestrate a full scan for the given scan_id."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run_scan_async(self, scan_id))
    finally:
        loop.close()


async def _run_scan_async(task, scan_id: str) -> dict:
    from scanr.core.engine import ScanEngine
    from scanr.models import Scan, ScanStatus
    from sqlalchemy import select

    SessionLocal = _make_session()
    async with SessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return {"error": "scan not found"}

        scan.started_at = datetime.now(tz=timezone.utc)
        scan.status = ScanStatus.running
        await db.commit()

        user_id = scan.user_id
        try:
            engine = ScanEngine(scan_id=scan_id, db=db)
            await engine.run()
            scan.status = ScanStatus.completed
        except asyncio.CancelledError:
            scan.status = ScanStatus.cancelled
            raise
        except Exception as exc:
            logger.exception("Scan %s failed: %s", scan_id, exc)
            scan.status = ScanStatus.failed
            scan.error_message = str(exc)
        finally:
            scan.finished_at = datetime.now(tz=timezone.utc)
            await db.commit()

        # Fire webhooks
        try:
            from scanr.core.webhook_dispatcher import dispatch
            event = "scan.completed" if scan.status == ScanStatus.completed else "scan.failed"
            await dispatch(event, {
                "scan_id": scan_id,
                "name": scan.name,
                "status": scan.status,
                "hosts_up": scan.hosts_up,
                "findings_critical": scan.findings_critical,
                "findings_high": scan.findings_high,
            }, user_id, db)
        except Exception as exc:
            logger.warning("Webhook dispatch failed for scan %s: %s", scan_id, exc)

    return {"scan_id": scan_id, "status": scan.status}
