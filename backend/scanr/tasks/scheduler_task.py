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

    # expire_on_commit=False: _fire_schedule commits mid-loop, and the default
    # expire-on-commit would make attribute access on the remaining schedule
    # objects raise MissingGreenlet in this async context.
    async with AsyncSession(engine, expire_on_commit=False) as session:
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

    from sqlalchemy import select

    from scanr.config import get_settings
    from scanr.models import Scan, ScanStatus, Target
    from scanr.models.base import new_uuid
    from scanr.models.credential import Credential
    from scanr.utils.ip_utils import classify_target, expand_targets, is_forbidden_target

    targets_raw: list[str] = json.loads(sched.targets) if sched.targets else []
    if not targets_raw:
        logger.warning("Schedule %s has no targets — skipping", sched.id)
        return

    # Defense in depth: re-validate at fire time. Targets are checked against
    # the denylist again and the referenced credential must still belong to the
    # schedule owner — both may have changed since the schedule was saved.
    denylist = get_settings().scan_denylist
    for raw in targets_raw:
        value = raw.strip()
        try:
            expanded = list(expand_targets(value))
        except ValueError:
            expanded = []
        if (
            not expanded
            or is_forbidden_target(value, denylist)
            or any(is_forbidden_target(ip, denylist) for ip in expanded)
        ):
            logger.warning(
                "Schedule %s target %r failed validation at fire time — skipping fire",
                sched.id, value,
            )
            sched.next_run = _calc_next_run(sched.cron_expr)
            await session.commit()
            return

    profile_data = json.loads(sched.scan_profile_json) if sched.scan_profile_json else {}

    credential_id = profile_data.get("credential_id")
    if credential_id:
        res = await session.execute(
            select(Credential.id).where(
                Credential.id == credential_id, Credential.user_id == sched.user_id
            )
        )
        if res.scalar_one_or_none() is None:
            logger.warning(
                "Schedule %s references a missing or foreign credential — skipping fire",
                sched.id,
            )
            sched.next_run = _calc_next_run(sched.cron_expr)
            await session.commit()
            return

    scan = Scan(
        id=new_uuid(),
        name=f"{sched.name} — {now.strftime('%Y-%m-%d %H:%M')} UTC",
        status=ScanStatus.pending,
        profile=profile_data.get("profile", "standard"),
        profile_json=sched.scan_profile_json,
        user_id=sched.user_id,
        credential_id=credential_id,
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

    sched.last_run = now
    sched.last_scan_id = scan.id
    sched.next_run = _calc_next_run(sched.cron_expr)

    # Commit BEFORE dispatching: the Celery worker must be able to see the scan
    # row. Dispatching against an uncommitted row races the worker and leaves
    # the scan stuck in 'pending' if the worker wins.
    scan_id = scan.id
    await session.commit()

    from scanr.tasks.scan_tasks import run_scan_task
    task = run_scan_task.delay(scan_id)

    scan.status = ScanStatus.running
    scan.celery_task_id = task.id
    await session.commit()

    logger.info("Fired schedule %r → scan %s (next: %s)", sched.name, scan_id, sched.next_run)
