"""Evidence attachments on findings: screenshots, saved requests, logs, PDFs."""
from __future__ import annotations

import re
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.core import evidence
from scanr.core.limiter import limiter
from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Finding, Scan
from scanr.models.base import new_uuid
from scanr.models.finding_attachment import FindingAttachment
from scanr.models.user import User

router = APIRouter(tags=["attachments"])
_MAX_PER_FINDING = 50


class AttachmentRead(BaseModel):
    id: str
    finding_id: str
    filename: str
    content_type: str
    size: int
    sha256: str
    caption: str | None
    uploaded_by: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AttachmentUpdate(BaseModel):
    caption: str | None = Field(None, max_length=2000)


def _safe_name(name: str | None, content_type: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", (name or "").strip())[:200].strip(" .")
    if not base:
        base = {"image/png": "screenshot.png", "image/jpeg": "screenshot.jpg", "image/gif": "image.gif",
                "image/webp": "image.webp", "application/pdf": "document.pdf"}.get(content_type, "evidence.txt")
    return base


async def _own_finding(db: AsyncSession, finding_id: str, user: User) -> Finding:
    finding = (await db.execute(
        select(Finding).join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.id == finding_id, Scan.user_id == user.id)
    )).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


async def _own_attachment(db: AsyncSession, attachment_id: str, user: User) -> FindingAttachment:
    attachment = (await db.execute(
        select(FindingAttachment)
        .join(Finding, FindingAttachment.finding_id == Finding.id)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(FindingAttachment.id == attachment_id, Scan.user_id == user.id)
    )).scalar_one_or_none()
    if attachment is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    return attachment


@router.get("/findings/{finding_id}/attachments", response_model=list[AttachmentRead])
async def list_attachments(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    await _own_finding(db, finding_id, current_user)
    rows = await db.execute(
        select(FindingAttachment).where(FindingAttachment.finding_id == finding_id).order_by(FindingAttachment.created_at)
    )
    return rows.scalars().all()


@router.post("/findings/{finding_id}/attachments", response_model=AttachmentRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("60/minute")
async def upload_attachment(
    request: Request,
    finding_id: str,
    file: UploadFile = File(...),
    caption: str = Form("", max_length=2000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:triage")),
):
    finding = await _own_finding(db, finding_id, current_user)
    count = len((await db.execute(
        select(FindingAttachment.id).where(FindingAttachment.finding_id == finding.id)
    )).all())
    if count >= _MAX_PER_FINDING:
        raise HTTPException(status_code=409, detail=f"A finding can have at most {_MAX_PER_FINDING} attachments")
    limit = get_settings().evidence_max_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"File exceeds {get_settings().evidence_max_mb} MB")
    if not data:
        raise HTTPException(status_code=400, detail="File is empty")
    try:
        content_type = evidence.detect_type(data)
    except evidence.EvidenceError as exc:
        raise HTTPException(status_code=415, detail=str(exc))

    attachment = FindingAttachment(
        id=new_uuid(), finding_id=finding.id, filename=_safe_name(file.filename, content_type),
        content_type=content_type, size=len(data), sha256="", caption=caption.strip() or None,
        uploaded_by=current_user.email,
    )
    attachment.sha256 = evidence.save(finding.id, attachment.id, data)
    db.add(attachment)
    try:
        await db.commit()
    except Exception:
        evidence.delete(finding.id, attachment.id)
        raise
    await db.refresh(attachment)
    return attachment


@router.get("/attachments/{attachment_id}/content")
async def download_attachment(
    attachment_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    attachment = await _own_attachment(db, attachment_id, current_user)
    path = evidence.path_for(attachment.finding_id, attachment.id)
    if not path.exists():
        raise HTTPException(status_code=410, detail="The evidence file is missing from storage")
    inline = attachment.content_type in evidence.IMAGE_TYPES
    return FileResponse(
        path,
        media_type=attachment.content_type,
        filename=attachment.filename,
        content_disposition_type="inline" if inline else "attachment",
        # SecurityHeadersMiddleware adds nosniff and CSP default-src 'none', so
        # even a mislabelled file could not run script.
        headers={"Cache-Control": "private, no-store"},
    )


@router.patch("/attachments/{attachment_id}", response_model=AttachmentRead)
async def update_attachment(
    attachment_id: str,
    body: AttachmentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:triage")),
):
    attachment = await _own_attachment(db, attachment_id, current_user)
    attachment.caption = (body.caption or "").strip() or None
    await db.commit()
    await db.refresh(attachment)
    return attachment


@router.delete("/attachments/{attachment_id}", status_code=204)
async def delete_attachment(
    attachment_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:triage")),
):
    attachment = await _own_attachment(db, attachment_id, current_user)
    finding_id = attachment.finding_id
    await db.delete(attachment)
    await db.commit()
    evidence.delete(finding_id, attachment_id)
