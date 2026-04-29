from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, select
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
    # Severity-weighted risk score: critical=40, high=10, medium=3, low=1
    risk_expr = func.sum(case(
        (Finding.severity == "critical", 40),
        (Finding.severity == "high", 10),
        (Finding.severity == "medium", 3),
        (Finding.severity == "low", 1),
        else_=0,
    )).label("risk_score")

    # Top severity — min of ordinal (critical=0 is worst)
    sev_order_expr = func.min(case(
        (Finding.severity == "critical", 0),
        (Finding.severity == "high", 1),
        (Finding.severity == "medium", 2),
        (Finding.severity == "low", 3),
        else_=4,
    )).label("top_sev_ord")

    result = await db.execute(
        select(
            Host.id, Host.ip, Host.hostname,
            func.count(Finding.id).label("finding_count"),
            risk_expr, sev_order_expr,
        )
        .join(Finding, Finding.host_id == Host.id)
        .join(Scan, Host.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.false_positive == False)
        .group_by(Host.id, Host.ip, Host.hostname)
        .order_by(risk_expr.desc())
        .limit(limit)
    )
    _sev = {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}
    return [
        {
            "id": r.id, "ip": r.ip, "hostname": r.hostname,
            "finding_count": r.finding_count,
            "risk_score": r.risk_score or 0,
            "top_severity": _sev.get(r.top_sev_ord, "info"),
        }
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


@router.get("/remediation-rate")
async def remediation_rate(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Ratio of resolved findings vs total non-FP findings, broken down by severity."""
    result = await db.execute(
        select(
            Finding.severity,
            Finding.remediation_status,
            func.count(Finding.id).label("cnt"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id, Finding.false_positive == False)
        .group_by(Finding.severity, Finding.remediation_status)
    )
    rows = result.all()
    totals: dict[str, int] = {}
    resolved: dict[str, int] = {}
    for row in rows:
        totals[row.severity] = totals.get(row.severity, 0) + row.cnt
        if row.remediation_status == "resolved":
            resolved[row.severity] = resolved.get(row.severity, 0) + row.cnt
    out = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        total = totals.get(sev, 0)
        res = resolved.get(sev, 0)
        out[sev] = {"total": total, "resolved": res, "rate": round(res / total, 3) if total else 0.0}
    return out


@router.get("/open-critical-age")
async def open_critical_age(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Days since creation for open critical/high findings (mean + max)."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(Finding.severity, Finding.created_at)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.user_id == current_user.id,
            Finding.false_positive == False,
            Finding.severity.in_(["critical", "high"]),
            Finding.remediation_status.in_(["open", None]),
        )
    )
    rows = result.all()
    ages_by_sev: dict[str, list[float]] = {"critical": [], "high": []}
    for row in rows:
        if row.created_at:
            dt = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=timezone.utc)
            ages_by_sev[row.severity].append((now - dt).total_seconds() / 86400)
    out = {}
    for sev, ages in ages_by_sev.items():
        out[sev] = {
            "count": len(ages),
            "mean_days": round(sum(ages) / len(ages), 1) if ages else 0.0,
            "max_days": round(max(ages), 1) if ages else 0.0,
        }
    return out


@router.get("/remediations")
async def remediation_groups(
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Group open findings by remediation text — shows what to fix and how many findings each fix closes."""
    result = await db.execute(
        select(
            Finding.remediation,
            Finding.severity,
            func.count(Finding.id).label("finding_count"),
            func.count(Host.ip.distinct()).label("host_count"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .outerjoin(Host, Finding.host_id == Host.id)
        .where(
            Scan.user_id == current_user.id,
            Finding.false_positive == False,
            Finding.remediation_status == "open",
            Finding.remediation.isnot(None),
            Finding.remediation != "",
        )
        .group_by(Finding.remediation, Finding.severity)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    )
    return [
        {
            "remediation": r.remediation,
            "severity": r.severity,
            "finding_count": r.finding_count,
            "host_count": r.host_count or 0,
        }
        for r in result.all()
    ]
