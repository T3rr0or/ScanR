from __future__ import annotations

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models import Host, Scan, ScanStatus, Target
from scanr.models.base import new_uuid
from scanr.models.user import User
from scanr.schemas import ScanCreate, ScanRead, ScanSummary
from scanr.schemas.host import HostRead
from scanr.core.limiter import limiter
from scanr.utils.ip_utils import classify_target

router = APIRouter(prefix="/scans", tags=["scans"])

# Valid port range: top-N, all, single port, range, comma list
_PORT_RANGE_RE = re.compile(r'^(top-\d{1,5}|all|\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$')


def _validate_profile_json(raw: str) -> str:
    try:
        pj = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="profile_json is not valid JSON")
    if not isinstance(pj, dict):
        raise HTTPException(status_code=400, detail="profile_json must be a JSON object")
    port_range = pj.get("port_range")
    if port_range is not None:
        if not isinstance(port_range, str) or not _PORT_RANGE_RE.match(port_range):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid port_range: {port_range!r}. Use e.g. 'top-1000', '80,443', '1-1024', 'all'.",
            )
    return raw


async def _get_own_scan(scan_id: str, user_id: str, db: AsyncSession) -> Scan:
    """Load a scan and verify it belongs to the requesting user. Raises 404 if not found."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("", response_model=list[ScanSummary])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(100)
    )
    return result.scalars().all()


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_scan(
    request: Request,
    body: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not body.targets:
        raise HTTPException(status_code=400, detail="At least one target required")

    if body.profile_json:
        body.profile_json = _validate_profile_json(body.profile_json)

    scan = Scan(
        id=new_uuid(),
        name=body.name,
        description=body.description,
        status=ScanStatus.pending,
        profile=body.profile,
        profile_json=body.profile_json,
        credential_id=body.credential_id,
        user_id=current_user.id,
    )
    db.add(scan)

    for raw in body.targets:
        target = Target(
            id=new_uuid(),
            scan_id=scan.id,
            value=raw.strip(),
            type=classify_target(raw.strip()),
        )
        db.add(target)

    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await _get_own_scan(scan_id, current_user.id, db)


@router.get("/{scan_id}/hosts", response_model=list[HostRead])
async def get_scan_hosts(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _get_own_scan(scan_id, current_user.id, db)
    from scanr.models.port import Port
    from scanr.models.service import Service
    result = await db.execute(
        select(Host)
        .where(Host.scan_id == scan_id)
        .options(selectinload(Host.ports).selectinload(Port.service))
    )
    return result.scalars().all()


@router.post("/{scan_id}/launch", status_code=status.HTTP_202_ACCEPTED)
async def launch_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = await _get_own_scan(scan_id, current_user.id, db)
    if scan.status == ScanStatus.running:
        raise HTTPException(status_code=409, detail="Scan already running")

    from scanr.tasks.scan_tasks import run_scan_task
    task = run_scan_task.delay(scan_id)
    scan.status = ScanStatus.running
    scan.celery_task_id = task.id
    await db.commit()
    return {"task_id": task.id, "scan_id": scan_id}


@router.post("/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = await _get_own_scan(scan_id, current_user.id, db)

    if scan.celery_task_id:
        from scanr.tasks.celery_app import celery_app
        celery_app.control.revoke(scan.celery_task_id, terminate=True, signal="SIGTERM")

    scan.status = ScanStatus.cancelled
    await db.commit()
    return {"status": "cancelled"}


@router.get("/{scan_id}/delta")
async def scan_delta(
    scan_id: str,
    baseline: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compare scan_id against baseline scan. Returns delta of hosts, ports, findings."""
    from scanr.core.delta_engine import compute_delta
    await _get_own_scan(scan_id, current_user.id, db)
    await _get_own_scan(baseline, current_user.id, db)
    return await compute_delta(baseline, scan_id, db)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _get_own_scan(scan_id, current_user.id, db)

    # Delete in FK dependency order (SQLAlchemy cascade doesn't fire without
    # eagerly-loaded relationships, so we use raw DELETE statements).
    sid = {"scan_id": scan_id}
    # 1. services → ports → hosts
    await db.execute(text(
        "DELETE FROM services WHERE port_id IN "
        "(SELECT p.id FROM ports p JOIN hosts h ON p.host_id = h.id WHERE h.scan_id = :scan_id)"
    ), sid)
    await db.execute(text(
        "DELETE FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE scan_id = :scan_id)"
    ), sid)
    # 2. screenshots
    await db.execute(text("DELETE FROM screenshots WHERE scan_id = :scan_id"), sid)
    # 3. nullify first_seen/last_seen refs in findings from OTHER scans
    await db.execute(text(
        "UPDATE findings SET first_seen_scan_id = NULL WHERE first_seen_scan_id = :scan_id"
    ), sid)
    await db.execute(text(
        "UPDATE findings SET last_seen_scan_id = NULL WHERE last_seen_scan_id = :scan_id"
    ), sid)
    # 4. findings, hosts, targets, reports, exclusions
    await db.execute(text("DELETE FROM findings WHERE scan_id = :scan_id"), sid)
    await db.execute(text("DELETE FROM hosts WHERE scan_id = :scan_id"), sid)
    await db.execute(text("DELETE FROM targets WHERE scan_id = :scan_id"), sid)
    await db.execute(text("DELETE FROM reports WHERE scan_id = :scan_id"), sid)
    await db.execute(text("DELETE FROM exclusions WHERE scan_id = :scan_id"), sid)
    # 5. scan itself
    await db.execute(text("DELETE FROM scans WHERE id = :scan_id"), sid)
    await db.commit()
