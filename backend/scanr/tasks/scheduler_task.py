"""
Celery Beat task: fires pending scheduled scans.
Runs every 60 seconds, checks for schedules whose next_run is overdue.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from scanr.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _calc_next_run(cron_expr: str) -> datetime | None:
    try:
        from apscheduler.triggers.cron import CronTrigger
        trigger = CronTrigger.from_crontab(cron_expr, timezone="UTC")
        return trigger.get_next_fire_time(None, datetime.now(timezone.utc))
    except Exception as exc:
        logger.warning("Invalid cron expression %r: %s", cron_expr, exc)
        return None


@celery_app.task(name="scanr.tasks.scheduler_task.check_schedules_task")
def check_schedules_task() -> None:
    """Celery Beat entry point."""
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_async_run_due_schedules())
    finally:
        loop.close()


async def _async_run_due_schedules() -> None:
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.pool import NullPool

    from scanr.config import get_settings
    from scanr.models.schedule import Schedule

    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    now = datetime.now(timezone.utc)

    async with AsyncSession(engine) as session:
        result = await session.execute(
            select(Schedule).where(
                Schedule.enabled == True,
                Schedule.next_run <= now,
            )
        )
        schedules = result.scalars().all()
        logger.info("Scheduler tick: %d due schedule(s)", len(schedules))

        for sched in schedules:
            try:
                await _fire_schedule(sched, session, now)
            except Exception as exc:
                logger.error("Failed to fire schedule %s: %s", sched.id, exc)

        await session.commit()

    await engine.dispose()


async def _fire_schedule(sched, session, now: datetime) -> None:

    from scanr.models import Scan, ScanStatus, Target
    from scanr.models.base import new_uuid
    from scanr.utils.ip_utils import classify_target

    targets_raw: list[str] = json.loads(sched.targets) if sched.targets else []
    if not targets_raw:
        logger.warning("Schedule %s has no targets — skipping", sched.id)
        return

    profile_data = json.loads(sched.scan_profile_json) if sched.scan_profile_json else {}

    scan = Scan(
        id=new_uuid(),
        name=f"{sched.name} — {now.strftime('%Y-%m-%d %H:%M')} UTC",
        status=ScanStatus.pending,
        profile=profile_data.get("profile", "standard"),
        profile_json=sched.scan_profile_json,
        user_id=sched.user_id,
        credential_id=profile_data.get("credential_id"),
        template_id=profile_data.get("template_id"),
    )
    session.add(scan)

    for raw in targets_raw:
        session.add(Target(
            id=new_uuid(),
            scan_id=scan.id,
            value=raw.strip(),
            type=classify_target(raw.strip()),
        ))

    await session.flush()

    from scanr.tasks.scan_tasks import run_scan_task
    task = run_scan_task.delay(scan.id)
    scan.status = ScanStatus.running
    scan.celery_task_id = task.id

    sched.last_run = now
    sched.last_scan_id = scan.id
    sched.next_run = _calc_next_run(sched.cron_expr)

    logger.info("Fired schedule %r → scan %s (next: %s)", sched.name, scan.id, sched.next_run)
