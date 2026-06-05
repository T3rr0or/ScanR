from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models import Finding, Host, Scan
from scanr.models.user import User

router = APIRouter(prefix="/assets", tags=["assets"])


class AssetItem(BaseModel):
    ip: str
    hostname: str | None
    os_name: str | None
    os_family: str | None
    last_seen_at: str | None
    first_seen_at: str | None
    scan_count: int
    findings_critical: int
    findings_high: int
    findings_medium: int
    findings_low: int
    risk_score: int


@router.get("", response_model=list[AssetItem])
async def list_assets(
    search: str | None = Query(None, description="Filter by IP or hostname substring"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cross-scan host inventory — aggregates all hosts by IP across all scans."""
    risk_expr = func.sum(case(
        (Finding.severity == "critical", 40),
        (Finding.severity == "high", 10),
        (Finding.severity == "medium", 3),
        (Finding.severity == "low", 1),
        else_=0,
    )).label("risk_score")

    q = (
        select(
            Host.ip,
            func.max(Host.hostname).label("hostname"),
            func.max(Host.os_name).label("os_name"),
            func.max(Host.os_family).label("os_family"),
            func.max(Scan.finished_at).label("last_seen_at"),
            func.min(Scan.started_at).label("first_seen_at"),
            func.count(Host.id.distinct()).label("scan_count"),
            func.sum(case((Finding.severity == "critical", 1), else_=0)).label("findings_critical"),
            func.sum(case((Finding.severity == "high", 1), else_=0)).label("findings_high"),
            func.sum(case((Finding.severity == "medium", 1), else_=0)).label("findings_medium"),
            func.sum(case((Finding.severity == "low", 1), else_=0)).label("findings_low"),
            risk_expr,
        )
        .join(Scan, Host.scan_id == Scan.id)
        .outerjoin(
            Finding,
            (Finding.host_id == Host.id) & (Finding.false_positive == False),
        )
        .where(Scan.user_id == current_user.id)
        .group_by(Host.ip)
        .order_by(risk_expr.desc())
        .limit(limit)
        .offset(offset)
    )

    if search:
        q = q.where((Host.ip.contains(search)) | (Host.hostname.contains(search)))

    result = await db.execute(q)
    rows = result.all()
    return [
        AssetItem(
            ip=r.ip,
            hostname=r.hostname,
            os_name=r.os_name,
            os_family=r.os_family,
            last_seen_at=r.last_seen_at.isoformat() if r.last_seen_at else None,
            first_seen_at=r.first_seen_at.isoformat() if r.first_seen_at else None,
            scan_count=r.scan_count or 0,
            findings_critical=r.findings_critical or 0,
            findings_high=r.findings_high or 0,
            findings_medium=r.findings_medium or 0,
            findings_low=r.findings_low or 0,
            risk_score=r.risk_score or 0,
        )
        for r in rows
    ]


@router.get("/{ip}/findings")
async def asset_findings(
    ip: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """All findings for a given IP across all scans, newest first."""
    from scanr.schemas import FindingRead
    result = await db.execute(
        select(Finding, Host.ip.label("host_ip"), Scan.name.label("scan_name"))
        .join(Host, Finding.host_id == Host.id)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Host.ip == ip, Scan.user_id == current_user.id)
        .order_by(Finding.created_at.desc())
        .limit(500)
    )
    rows = result.all()
    findings = []
    for row in rows:
        f = FindingRead.model_validate(row[0])
        f.host_ip = row[1]
        findings.append(f)
    return findings
