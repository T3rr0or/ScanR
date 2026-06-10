from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from celery.exceptions import SoftTimeLimitExceeded

from .celery_app import celery_app

logger = logging.getLogger(__name__)


def _make_engine_and_session():
    """Create a fresh async engine + session bound to the current event loop.

    Celery workers run each task in a new event loop.  The shared engine in
    session.py uses asyncpg's connection pool which is tied to the loop that
    created it — reusing it across loops causes 'Future attached to a
    different loop' errors.  NullPool skips pooling entirely so every call
    opens a fresh connection on whatever loop is active.

    Caller is responsible for calling await engine.dispose() to release
    the connection.
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
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)
    return engine, session_maker


@celery_app.task(bind=True, name="scanr.run_scan")
def run_scan_task(self, scan_id: str) -> dict:
    """Celery task: orchestrate a full scan for the given scan_id."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run_scan_async(self, scan_id))
    except SoftTimeLimitExceeded:
        logger.warning("Scan %s hit soft time limit — marking as failed", scan_id)
        loop.close()
        cleanup_loop = asyncio.new_event_loop()
        try:
            cleanup_loop.run_until_complete(
                _mark_scan_terminal(scan_id, "Task exceeded time limit")
            )
        finally:
            cleanup_loop.close()
        raise
    finally:
        if not loop.is_closed():
            loop.close()


async def _set_short_lock_timeout(db, seconds: int = 2) -> None:
    """Keep maintenance updates from blocking behind long scan transactions."""
    from scanr.config import get_settings
    from sqlalchemy import text

    if get_settings().database_url.startswith("postgres"):
        # Postgres SET does not reliably accept bind params across drivers.
        # Keep value static/safe; caller only needs a short timeout.
        await db.execute(text("SET LOCAL lock_timeout = '2000ms'"))


async def _heartbeat_loop(scan_id: str, interval: int = 30) -> None:
    """Periodically stamp scans.last_heartbeat while a scan runs.

    Uses its own engine/session so it never contends with the engine's session.
    A stale heartbeat is how the watchdog detects a worker that died mid-scan.
    """
    from scanr.models import Scan
    from sqlalchemy import update

    engine, SessionLocal = _make_engine_and_session()
    try:
        while True:
            await asyncio.sleep(interval)
            try:
                async with SessionLocal() as db:
                    await _set_short_lock_timeout(db)
                    await db.execute(
                        update(Scan)
                        .where(Scan.id == scan_id)
                        .values(last_heartbeat=datetime.now(tz=timezone.utc))
                    )
                    await db.commit()
            except Exception as exc:  # never let heartbeat failure kill the scan
                logger.warning("heartbeat update failed for scan %s: %s", scan_id, exc)
    finally:
        await engine.dispose()


async def _mark_scan_terminal(scan_id: str, reason: str) -> None:
    from scanr.models import Scan, ScanStatus
    from sqlalchemy import select

    engine, SessionLocal = _make_engine_and_session()
    try:
        async with SessionLocal() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan and scan.status == ScanStatus.running:
                scan.status = ScanStatus.failed
                scan.error_message = reason
                scan.finished_at = datetime.now(tz=timezone.utc)
                await db.commit()
    finally:
        await engine.dispose()


@celery_app.task(name="scanr.reap_stale_scans")
def reap_stale_scans() -> dict:
    """Periodic watchdog: fail scans whose worker heartbeat has gone stale.

    If a worker is OOM-killed or SIGKILLed mid-scan, the scan row stays in
    "running" forever. This marks such scans failed once their heartbeat is
    older than ``scan_heartbeat_timeout``.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_reap_stale_scans_async())
    finally:
        loop.close()


async def _reap_stale_scans_async() -> dict:
    from datetime import timedelta

    from scanr.config import get_settings
    from scanr.models import Scan, ScanStatus
    from sqlalchemy import or_, select, update

    settings = get_settings()
    cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=settings.scan_heartbeat_timeout)

    engine, SessionLocal = _make_engine_and_session()
    try:
        async with SessionLocal() as db:
            try:
                await _set_short_lock_timeout(db)
                # A scan is stale if it's running but its last heartbeat (or, for
                # older rows, its start time) is older than the cutoff. Skip rows
                # currently locked by an active scan transaction so the watchdog
                # never queues behind normal result writes or races completion.
                result = await db.execute(
                    select(Scan.id)
                    .where(
                        Scan.status == ScanStatus.running,
                        or_(
                            Scan.last_heartbeat < cutoff,
                            (Scan.last_heartbeat.is_(None)) & (Scan.started_at < cutoff),
                        ),
                    )
                    .with_for_update(skip_locked=True)
                )
                stale_ids = [row[0] for row in result.all()]
                if stale_ids:
                    await db.execute(
                        update(Scan)
                        .where(Scan.id.in_(stale_ids), Scan.status == ScanStatus.running)
                        .values(
                            status=ScanStatus.failed,
                            error_message="Scan worker stopped responding (heartbeat timeout)",
                            finished_at=datetime.now(tz=timezone.utc),
                        )
                    )
                    await db.commit()
                    logger.warning("Reaped %d stale scan(s): %s", len(stale_ids), stale_ids)
                else:
                    await db.commit()
                return {"reaped": len(stale_ids)}
            except Exception as exc:
                await db.rollback()
                logger.warning("stale-scan reaper skipped after lock timeout/error: %s", exc)
                return {"reaped": 0, "error": str(exc)}
    finally:
        await engine.dispose()


async def _run_scan_async(task, scan_id: str) -> dict:
    from scanr.core.engine import ScanEngine
    from scanr.models import Scan, ScanStatus
    from sqlalchemy import select

    db_engine, SessionLocal = _make_engine_and_session()
    try:
        async with SessionLocal() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                logger.error("Scan %s not found", scan_id)
                return {"error": "scan not found"}

            now = datetime.now(tz=timezone.utc)
            scan.started_at = now
            scan.last_heartbeat = now
            scan.status = ScanStatus.running
            await db.commit()

            user_id = scan.user_id
            heartbeat = asyncio.create_task(_heartbeat_loop(scan_id))
            try:
                scan_engine = ScanEngine(scan_id=scan_id, db=db)
                await scan_engine.run()
                scan.status = ScanStatus.completed
                scan.error_message = None
            except asyncio.CancelledError:
                scan.status = ScanStatus.cancelled
                raise
            except Exception as exc:
                logger.exception("Scan %s failed: %s", scan_id, exc)
                scan.status = ScanStatus.failed
                scan.error_message = str(exc)
            finally:
                heartbeat.cancel()
                try:
                    await heartbeat
                except (asyncio.CancelledError, Exception):
                    pass
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
    finally:
        await db_engine.dispose()

    return {"scan_id": scan_id, "status": scan.status}
