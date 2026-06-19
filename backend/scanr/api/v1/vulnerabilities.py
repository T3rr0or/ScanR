from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models import Finding, Host, Scan
from scanr.models.user import User

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


class VulnerabilityItem(BaseModel):
    plugin_id: str
    title: str
    severity: str
    total_instances: int
    host_count: int
    open_count: int
    first_seen_at: str | None
    last_seen_at: str | None
    max_cvss: float | None
    max_vpr: float | None


@router.get("", response_model=list[VulnerabilityItem])
async def list_vulnerabilities(
    severity: str | None = Query(None),
    search: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Vulnerability-centric view — groups findings by plugin_id across all scans."""
    # Filter conditions applied consistently to BOTH the host-count subquery and
    # the main query, so the displayed counts always reflect the active filter.
    filters = [Scan.user_id == current_user.id, Finding.false_positive == False]
    if severity:
        filters.append(Finding.severity == severity)
    if search:
        like = f"%{search}%"
        # ilike → case-insensitive (LIKE is case-sensitive on PostgreSQL)
        filters.append(Finding.plugin_id.ilike(like) | Finding.title.ilike(like))

    # Subquery: distinct host count per plugin
    host_subq = (
        select(Finding.plugin_id, func.count(Host.ip.distinct()).label("host_count"))
        .join(Scan, Finding.scan_id == Scan.id)
        .outerjoin(Host, Finding.host_id == Host.id)
        .where(*filters)
        .group_by(Finding.plugin_id)
        .subquery()
    )

    q = (
        select(
            Finding.plugin_id,
            Finding.title,
            Finding.severity,
            func.count(Finding.id).label("total_instances"),
            host_subq.c.host_count,
            func.sum(case((Finding.remediation_status == "open", 1), else_=0)).label("open_count"),
            func.min(Finding.created_at).label("first_seen_at"),
            func.max(Finding.created_at).label("last_seen_at"),
            func.max(Finding.cvss_score).label("max_cvss"),
            func.max(Finding.vpr_score).label("max_vpr"),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .join(host_subq, host_subq.c.plugin_id == Finding.plugin_id)
        .where(*filters)
        .group_by(Finding.plugin_id, Finding.title, Finding.severity, host_subq.c.host_count)
        .order_by(func.max(Finding.vpr_score).desc().nulls_last(), func.count(Finding.id).desc())
        .limit(limit)
        .offset(offset)
    )

    result = await db.execute(q)
    rows = result.all()
    return [
        VulnerabilityItem(
            plugin_id=r.plugin_id,
            title=r.title,
            severity=r.severity,
            total_instances=r.total_instances,
            host_count=r.host_count or 0,
            open_count=r.open_count or 0,
            first_seen_at=r.first_seen_at.isoformat() if r.first_seen_at else None,
            last_seen_at=r.last_seen_at.isoformat() if r.last_seen_at else None,
            max_cvss=r.max_cvss,
            max_vpr=r.max_vpr,
        )
        for r in rows
    ]


@router.get("/{plugin_id}/hosts")
async def vulnerability_hosts(
    plugin_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """All hosts affected by a given plugin_id across all scans."""
    result = await db.execute(
        select(
            Host.ip,
            Host.hostname,
            Finding.id.label("finding_id"),
            Finding.port_number,
            Finding.remediation_status,
            Finding.false_positive,
            Scan.name.label("scan_name"),
            Scan.id.label("scan_id"),
            Finding.created_at,
        )
        .join(Host, Finding.host_id == Host.id)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.plugin_id == plugin_id, Scan.user_id == current_user.id)
        .order_by(Finding.created_at.desc())
        .limit(500)
    )
    rows = result.all()
    return [
        {
            "ip": r.ip,
            "hostname": r.hostname,
            "finding_id": r.finding_id,
            "port_number": r.port_number,
            "remediation_status": r.remediation_status,
            "false_positive": r.false_positive,
            "scan_name": r.scan_name,
            "scan_id": r.scan_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
