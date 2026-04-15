from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models import Finding, Host, Scan
from scanr.models.user import User

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/severity-distribution")
async def severity_distribution(
    scan_id: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = (
        select(Finding.severity, func.count(Finding.id).label("count"))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.false_positive == False)
    )
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    q = q.group_by(Finding.severity)
    result = await db.execute(q)
    rows = result.all()
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in rows:
        dist[row.severity] = row.count
    return dist


@router.get("/findings-timeline")
async def findings_timeline(
    days: int = Query(30, ge=7, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(Finding.severity, Finding.created_at)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.user_id == current_user.id,
            Finding.created_at >= cutoff,
            Finding.false_positive == False,
        )
    )
    rows = result.all()

    # Bucket by date
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    for row in rows:
        date_key = row.created_at.strftime("%Y-%m-%d")
        buckets[date_key][row.severity] += 1

    # Fill missing days
    out = []
    for i in range(days):
        day = (datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        entry = {"date": day, **buckets[day]}
        out.append(entry)
    return out


@router.get("/top-vulnerable-hosts")
async def top_vulnerable_hosts(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(
            Host.id,
            Host.ip,
            Host.hostname,
            func.count(Finding.id).label("finding_count"),
        )
        .join(Finding, Finding.host_id == Host.id)
        .join(Scan, Host.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.false_positive == False)
        .group_by(Host.id, Host.ip, Host.hostname)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    )
    return [
        {"id": r.id, "ip": r.ip, "hostname": r.hostname, "finding_count": r.finding_count}
        for r in result.all()
    ]


@router.get("/scan-activity")
async def scan_activity(
    days: int = Query(30, ge=7, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(Scan.started_at, Scan.status)
        .where(Scan.user_id == current_user.id, Scan.started_at >= cutoff)
    )
    rows = result.all()

    buckets: dict[str, int] = defaultdict(int)
    for row in rows:
        if row.started_at:
            buckets[row.started_at.strftime("%Y-%m-%d")] += 1

    out = []
    for i in range(days):
        day = (datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        out.append({"date": day, "scans": buckets[day]})
    return out


@router.get("/plugin-hit-rate")
async def plugin_hit_rate(
    limit: int = Query(20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Finding.plugin_id, func.count(Finding.id).label("hit_count"))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.false_positive == False)
        .group_by(Finding.plugin_id)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    )
    return [{"plugin_id": r.plugin_id, "hit_count": r.hit_count} for r in result.all()]
