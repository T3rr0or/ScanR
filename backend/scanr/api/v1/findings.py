from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.core.limiter import limiter
from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Finding, Host, Scan
from scanr.models.user import User
from scanr.schemas import FindingBulkUpdate, FindingRead, FindingUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingRead])
async def list_findings(
    scan_id: str | None = Query(None),
    host_id: str | None = Query(None),
    severity: str | None = Query(None),
    plugin_id: str | None = Query(None),
    false_positive: bool | None = Query(None),
    mitre_technique: str | None = Query(None, description="Filter by ATT&CK technique ID, e.g. T1110.001"),
    compliance_tag: str | None = Query(None, description="Filter by compliance framework prefix or tag, e.g. 'PCI-DSS' or 'PCI-DSS:6.4.1'"),
    limit: int = Query(200, le=500),
    cursor: str | None = Query(None, description="Cursor from previous page: ISO timestamp,finding_id"),
    offset: int = Query(0, description="Deprecated: use cursor instead"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    q = (
        select(Finding, Host.ip.label("host_ip"))
        .outerjoin(Host, Finding.host_id == Host.id)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .order_by(Finding.created_at.desc(), Finding.id.desc())
    )
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if host_id:
        q = q.where(Finding.host_id == host_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if plugin_id:
        q = q.where(Finding.plugin_id == plugin_id)
    if false_positive is not None:
        q = q.where(Finding.false_positive == false_positive)
    if mitre_technique:
        if not re.match(r'^T\d{4}(\.\d{3})?$', mitre_technique):
            raise HTTPException(status_code=400, detail="Invalid MITRE technique ID (e.g. T1110 or T1110.001)")
        q = q.where(Finding.mitre_tags.contains(mitre_technique))
    if compliance_tag:
        # Validate format — only allow alphanumeric, colon, dot, hyphen (e.g. PCI-DSS:6.4.1)
        if not re.match(r'^[A-Z0-9][A-Z0-9:.\-]{1,40}$', compliance_tag, re.IGNORECASE):
            raise HTTPException(status_code=400, detail="Invalid compliance tag format (e.g. 'PCI-DSS' or 'PCI-DSS:6.4.1')")
        q = q.where(Finding.compliance_tags.contains(compliance_tag))

    # Cursor takes precedence over offset — stable under concurrent inserts
    if cursor:
        try:
            cur_ts_str, cur_id = cursor.rsplit(",", 1)
            cur_ts = datetime.fromisoformat(cur_ts_str)
            q = q.where(
                (Finding.created_at < cur_ts) |
                ((Finding.created_at == cur_ts) & (Finding.id < cur_id))
            )
        except (ValueError, AttributeError):
            raise HTTPException(status_code=400, detail="Invalid cursor format")
    else:
        q = q.offset(offset)

    q = q.limit(limit)
    result = await db.execute(q)
    rows = result.all()
    findings = []
    for row in rows:
        f = row[0]
        ip = row[1]
        d = FindingRead.model_validate(f)
        d.host_ip = ip
        findings.append(d)
    return findings


@router.get("/export")
@limiter.limit("10/minute")
async def export_findings(
    request: Request,
    scan_id: str | None = Query(None),
    severity: str | None = Query(None),
    plugin_id: str | None = Query(None),
    false_positive: bool | None = Query(None),
    compliance_tag: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    """Stream findings as CSV — respects all standard filter params.

    Registered before ``/{finding_id}`` so the literal path is not shadowed by
    the dynamic route.
    """
    import csv
    import io
    from fastapi.responses import StreamingResponse

    q = (
        select(Finding, Host.ip.label("host_ip"))
        .outerjoin(Host, Finding.host_id == Host.id)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .order_by(Finding.severity, Finding.created_at.desc())
    )
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if plugin_id:
        q = q.where(Finding.plugin_id == plugin_id)
    if false_positive is not None:
        q = q.where(Finding.false_positive == false_positive)
    if compliance_tag:
        if not re.match(r'^[A-Z0-9][A-Z0-9:.\-]{1,40}$', compliance_tag, re.IGNORECASE):
            raise HTTPException(status_code=400, detail="Invalid compliance tag format")
        q = q.where(Finding.compliance_tags.contains(compliance_tag))

    result = await db.execute(q.limit(5000))
    rows = result.all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["severity", "title", "host_ip", "plugin_id", "cvss_score", "port",
                     "false_positive", "remediation_status", "analyst_notes",
                     "description", "remediation"])
    for row in rows:
        f, ip = row[0], row[1]
        writer.writerow([
            f.severity, f.title, ip or "", f.plugin_id, f.cvss_score or "",
            f"{f.port_number}/{f.protocol}" if f.port_number else "",
            "yes" if f.false_positive else "", f.remediation_status or "",
            (f.analyst_notes or "").replace("\n", " "),
            (f.description or "").replace("\n", " ")[:300],
            (f.remediation or "").replace("\n", " ")[:200],
        ])

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@router.get("/{finding_id}", response_model=FindingRead)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.user_id == current_user.id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingRead)
async def update_finding(
    finding_id: str,
    body: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:triage")),
):
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.user_id == current_user.id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if body.false_positive is not None:
        finding.false_positive = body.false_positive
        if body.false_positive and not finding.triaged_at:
            finding.triaged_at = datetime.now(timezone.utc)
            finding.triaged_by = current_user.email
    if body.analyst_notes is not None:
        finding.analyst_notes = body.analyst_notes
    if body.remediation_status is not None:
        finding.remediation_status = body.remediation_status
        if body.remediation_status != "open":
            finding.triaged_at = datetime.now(timezone.utc)
            finding.triaged_by = current_user.email

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/bulk", status_code=200)
async def bulk_update_findings(
    body: FindingBulkUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:triage")),
):
    if not body.ids:
        return {"updated": 0}
    if len(body.ids) > 500:
        raise HTTPException(status_code=400, detail="Cannot bulk-update more than 500 findings at once")
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id.in_(body.ids), Scan.user_id == current_user.id)
    )
    findings = result.scalars().all()
    now = datetime.now(timezone.utc)
    is_triage_action = (
        body.false_positive is not None
        or (body.remediation_status is not None and body.remediation_status != "open")
    )
    for finding in findings:
        if body.false_positive is not None:
            finding.false_positive = body.false_positive
        if body.analyst_notes is not None:
            finding.analyst_notes = body.analyst_notes
        if body.remediation_status is not None:
            finding.remediation_status = body.remediation_status
        if is_triage_action:
            finding.triaged_at = now
            finding.triaged_by = current_user.email
    await db.commit()
    return {"updated": len(findings)}


@router.get("/{finding_id}/history")
async def finding_history(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    """All appearances of the same vulnerability ordered by date."""
    from scanr.models import Scan as _Scan
    # Load target finding first to get its canonical key
    target_result = await db.execute(
        select(Finding, Host.ip.label("host_ip"), _Scan.name.label("sname"))
        .outerjoin(Host, Finding.host_id == Host.id)
        .join(_Scan, Finding.scan_id == _Scan.id)
        .where(Finding.id == finding_id, _Scan.user_id == current_user.id)
    )
    row = target_result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    target = row[0]
    target_host_ip = row.host_ip

    history_result = await db.execute(
        select(Finding, _Scan.name.label("scan_name"), _Scan.finished_at.label("scan_date"))
        .outerjoin(Host, Finding.host_id == Host.id)
        .join(_Scan, Finding.scan_id == _Scan.id)
        .where(
            _Scan.user_id == current_user.id,
            Finding.plugin_id == target.plugin_id,
            Finding.title == target.title,
            Finding.port_number == target.port_number,
            Finding.protocol == target.protocol,
            Host.ip == target_host_ip,
        )
        .order_by(Finding.created_at.asc())
    )
    return [
        {
            "finding_id": r[0].id,
            "scan_id": r[0].scan_id,
            "scan_name": r.scan_name,
            "scan_date": r.scan_date.isoformat() if r.scan_date else None,
            "remediation_status": r[0].remediation_status,
            "false_positive": r[0].false_positive,
            "created_at": r[0].created_at.isoformat() if r[0].created_at else None,
        }
        for r in history_result.all()
    ]
