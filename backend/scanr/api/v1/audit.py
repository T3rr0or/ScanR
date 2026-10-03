"""Read the audit trail (administrators only). There is no write or delete API."""
from __future__ import annotations

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import require_admin_scope
from scanr.models.audit_event import AuditEvent
from scanr.models.user import User
from scanr.reporting.csv_safety import spreadsheet_safe_cell

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventRead(BaseModel):
    id: str
    created_at: datetime
    user_id: str | None
    user_email: str | None
    auth_method: str | None
    ip: str | None
    action: str
    target_type: str | None
    target_id: str | None
    method: str | None
    path: str | None
    status_code: int | None
    details: str | None

    model_config = {"from_attributes": True}


def _query(user: str | None, action: str | None, target_id: str | None,
           since: datetime | None, until: datetime | None, outcome: str | None):
    q = select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
    if user:
        q = q.where(AuditEvent.user_email.ilike(f"%{user}%"))
    if action:
        q = q.where(AuditEvent.action.startswith(action))
    if target_id:
        q = q.where(AuditEvent.target_id == target_id)
    if since:
        q = q.where(AuditEvent.created_at >= since)
    if until:
        q = q.where(AuditEvent.created_at <= until)
    if outcome == "denied":
        q = q.where(AuditEvent.status_code >= 400)
    elif outcome == "allowed":
        q = q.where(AuditEvent.status_code < 400)
    return q


@router.get("", response_model=list[AuditEventRead])
async def list_events(
    user: str | None = Query(None, max_length=255, description="Email substring"),
    action: str | None = Query(None, max_length=100, description="Action prefix, e.g. 'auth.' or 'scans.launch'"),
    target_id: str | None = Query(None, max_length=100),
    since: datetime | None = None,
    until: datetime | None = None,
    outcome: str | None = Query(None, pattern="^(allowed|denied)$"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_scope("audit:read")),
):
    q = _query(user, action, target_id, since, until, outcome).limit(limit).offset(offset)
    return (await db.execute(q)).scalars().all()


@router.get("/export")
async def export_events(
    user: str | None = Query(None, max_length=255),
    action: str | None = Query(None, max_length=100),
    target_id: str | None = Query(None, max_length=100),
    since: datetime | None = None,
    until: datetime | None = None,
    outcome: str | None = Query(None, pattern="^(allowed|denied)$"),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_scope("audit:read")),
):
    rows = (await db.execute(_query(user, action, target_id, since, until, outcome).limit(100_000))).scalars().all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    columns = ["created_at", "user_email", "auth_method", "ip", "action", "target_type", "target_id",
               "method", "path", "status_code", "details"]
    writer.writerow(columns)
    for event in rows:
        writer.writerow([spreadsheet_safe_cell("" if getattr(event, c) is None else str(getattr(event, c)))
                         for c in columns])
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scanr-audit-log.csv"},
    )
