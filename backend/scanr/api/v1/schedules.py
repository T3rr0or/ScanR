from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Schedule
from scanr.models.base import new_uuid
from scanr.models.user import User

# Schedules launch scans, so they reuse the scans scopes. Target denylist and
# credential-ownership validation mirror the scans create path — a schedule
# must not be a way to bypass either.

router = APIRouter(prefix="/schedules", tags=["schedules"])


_MIN_INTERVAL_SECONDS = 3600  # schedules must be at least 1 hour apart
_MAX_SCHEDULES_PER_USER = 20


def _calc_next_run(cron_expr: str) -> datetime | None:
    try:
        from apscheduler.triggers.cron import CronTrigger
        trigger = CronTrigger.from_crontab(cron_expr, timezone="UTC")
        return trigger.get_next_fire_time(None, datetime.now(timezone.utc))
    except Exception:
        return None


def _validate_cron_interval(cron_expr: str) -> None:
    """Reject cron expressions that fire more often than once per hour."""
    try:
        from apscheduler.triggers.cron import CronTrigger
        trigger = CronTrigger.from_crontab(cron_expr, timezone="UTC")
        now = datetime.now(timezone.utc)
        first = trigger.get_next_fire_time(None, now)
        second = trigger.get_next_fire_time(first, first) if first else None
        if first and second:
            gap = (second - first).total_seconds()
            if gap < _MIN_INTERVAL_SECONDS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Schedule interval too frequent ({int(gap)}s). Minimum interval is 1 hour.",
                )
    except HTTPException:
        raise
    except Exception:
        pass


class ScheduleCreate(BaseModel):
    name: str
    description: str | None = None
    targets: list[str]
    scan_profile_json: str = "{}"
    cron_expr: str
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    targets: list[str] | None = None
    scan_profile_json: str | None = None
    cron_expr: str | None = None
    enabled: bool | None = None


class ScheduleRead(BaseModel):
    id: str
    name: str
    description: str | None
    targets: list[str]
    cron_expr: str
    enabled: bool
    next_run: datetime | None
    last_run: datetime | None
    last_scan_id: str | None
    scan_profile_json: str
    created_at: datetime

    model_config = {"from_attributes": True}


def _parse_schedule_profile(raw: str) -> dict:
    try:
        data = json.loads(raw or "{}")
    except Exception:
        raise HTTPException(status_code=400, detail="scan_profile_json is not valid JSON")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="scan_profile_json must be a JSON object")
    return data


async def _validate_schedule_inputs(
    targets: list[str], scan_profile_json: str, user_id: str, db: AsyncSession
) -> None:
    """Apply the same target denylist and credential-ownership checks as scan creation."""
    from scanr.api.v1.scans import _validate_targets, _verify_credential_owner

    if not targets:
        raise HTTPException(status_code=400, detail="At least one target required")
    await _validate_targets(targets)
    profile_data = _parse_schedule_profile(scan_profile_json)
    await _verify_credential_owner(profile_data.get("credential_id"), user_id, db)


def _to_read(s: Schedule) -> ScheduleRead:
    targets = json.loads(s.targets) if s.targets else []
    return ScheduleRead(
        id=s.id,
        name=s.name,
        description=s.description,
        targets=targets,
        cron_expr=s.cron_expr,
        enabled=s.enabled,
        next_run=s.next_run,
        last_run=s.last_run,
        last_scan_id=s.last_scan_id,
        scan_profile_json=s.scan_profile_json or "{}",
        created_at=s.created_at,
    )


@router.get("", response_model=list[ScheduleRead])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:read")),
):
    result = await db.execute(
        select(Schedule)
        .where(Schedule.user_id == current_user.id)
        .order_by(Schedule.name)
    )
    return [_to_read(s) for s in result.scalars().all()]


@router.post("", response_model=ScheduleRead, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    body: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    await _validate_schedule_inputs(body.targets, body.scan_profile_json, current_user.id, db)

    # Enforce per-user schedule quota
    count_result = await db.execute(
        select(Schedule).where(Schedule.user_id == current_user.id)
    )
    if len(count_result.scalars().all()) >= _MAX_SCHEDULES_PER_USER:
        raise HTTPException(status_code=400, detail=f"Maximum {_MAX_SCHEDULES_PER_USER} schedules per user")

    next_run = _calc_next_run(body.cron_expr)
    if next_run is None:
        raise HTTPException(status_code=400, detail=f"Invalid cron expression: {body.cron_expr!r}")

    _validate_cron_interval(body.cron_expr)

    schedule = Schedule(
        id=new_uuid(),
        user_id=current_user.id,
        name=body.name,
        description=body.description,
        targets=json.dumps(body.targets),
        scan_profile_json=body.scan_profile_json,
        cron_expr=body.cron_expr,
        enabled=body.enabled,
        next_run=next_run,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return _to_read(schedule)


@router.put("/{schedule_id}", response_model=ScheduleRead)
async def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    result = await db.execute(
        select(Schedule).where(Schedule.id == schedule_id, Schedule.user_id == current_user.id)
    )
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if body.name is not None:
        sched.name = body.name
    if body.description is not None:
        sched.description = body.description
    if body.targets is not None or body.scan_profile_json is not None:
        # Validate the effective post-update combination, not just the delta.
        new_targets = body.targets if body.targets is not None else json.loads(sched.targets or "[]")
        new_profile = body.scan_profile_json if body.scan_profile_json is not None else (sched.scan_profile_json or "{}")
        await _validate_schedule_inputs(new_targets, new_profile, current_user.id, db)
        sched.targets = json.dumps(new_targets)
        sched.scan_profile_json = new_profile
    if body.cron_expr is not None:
        next_run = _calc_next_run(body.cron_expr)
        if next_run is None:
            raise HTTPException(status_code=400, detail=f"Invalid cron expression: {body.cron_expr!r}")
        _validate_cron_interval(body.cron_expr)
        sched.cron_expr = body.cron_expr
        sched.next_run = next_run
    if body.enabled is not None:
        sched.enabled = body.enabled

    await db.commit()
    await db.refresh(sched)
    return _to_read(sched)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    result = await db.execute(
        select(Schedule).where(Schedule.id == schedule_id, Schedule.user_id == current_user.id)
    )
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.delete(sched)
    await db.commit()
