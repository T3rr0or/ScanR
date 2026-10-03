"""The finding library: the team's reviewed write-ups, shared by all users.

Reading needs findings:read; changing it needs findings:triage, so viewers
can use the library but not edit it.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Finding
from scanr.models.finding_template import FindingTemplate
from scanr.models.user import User

router = APIRouter(prefix="/library", tags=["library"])

Severity = Literal["critical", "high", "medium", "low", "info"]


def _strings(values: list[str] | None) -> list[str]:
    return [v.strip() for v in values or [] if v and v.strip()]


class TemplateIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    severity: Severity
    cvss_score: float | None = Field(None, ge=0, le=10)
    cvss_vector: str | None = Field(None, max_length=255)
    description: str = Field(..., min_length=1, max_length=50_000)
    impact: str | None = Field(None, max_length=50_000)
    remediation: str | None = Field(None, max_length=50_000)
    references: list[str] = Field(default_factory=list, max_length=100)
    cve_ids: list[str] = Field(default_factory=list, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=50)
    plugin_ids: list[str] = Field(default_factory=list, max_length=100)
    title_match: str | None = Field(None, max_length=255)

    @field_validator("references", "cve_ids", "tags", "plugin_ids")
    @classmethod
    def _clean(cls, v: list[str]) -> list[str]:
        return _strings(v)


class TemplateRead(TemplateIn):
    id: str
    created_by: str | None
    updated_by: str | None
    created_at: datetime
    updated_at: datetime
    usage_count: int = 0


def _read(t: FindingTemplate, usage: int = 0) -> TemplateRead:
    def lst(raw: str | None) -> list[str]:
        return json.loads(raw) if raw else []

    return TemplateRead(
        id=t.id, title=t.title, severity=t.severity, cvss_score=t.cvss_score, cvss_vector=t.cvss_vector,  # type: ignore[arg-type]
        description=t.description, impact=t.impact, remediation=t.remediation,
        references=lst(t.references), cve_ids=lst(t.cve_ids), tags=lst(t.tags),
        plugin_ids=lst(t.plugin_ids), title_match=t.title_match,
        created_by=t.created_by, updated_by=t.updated_by, created_at=t.created_at, updated_at=t.updated_at,
        usage_count=usage,
    )


def _store(t: FindingTemplate, body: TemplateIn) -> None:
    t.title = body.title.strip()
    t.severity = body.severity
    t.cvss_score = body.cvss_score
    t.cvss_vector = body.cvss_vector or None
    t.description = body.description
    t.impact = body.impact or None
    t.remediation = body.remediation or None
    t.references = json.dumps(body.references) if body.references else None
    t.cve_ids = json.dumps([c.upper() for c in body.cve_ids]) if body.cve_ids else None
    t.tags = json.dumps(body.tags) if body.tags else None
    t.plugin_ids = json.dumps(body.plugin_ids) if body.plugin_ids else None
    t.title_match = body.title_match or None


async def _title_taken(db: AsyncSession, title: str, exclude_id: str | None = None) -> bool:
    q = select(FindingTemplate.id).where(func.lower(FindingTemplate.title) == title.strip().lower())
    if exclude_id:
        q = q.where(FindingTemplate.id != exclude_id)
    return (await db.execute(q)).first() is not None


@router.get("", response_model=list[TemplateRead])
async def list_templates(
    q: str | None = Query(None, max_length=200, description="Search title, description and tags"),
    severity: Severity | None = None,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_scope("findings:read")),
):
    query = select(FindingTemplate).order_by(FindingTemplate.title)
    if q:
        like = f"%{q}%"
        query = query.where(or_(FindingTemplate.title.ilike(like), FindingTemplate.description.ilike(like),
                                FindingTemplate.tags.ilike(like)))
    if severity:
        query = query.where(FindingTemplate.severity == severity)
    templates = (await db.execute(query)).scalars().all()
    usage = dict((await db.execute(
        select(Finding.template_id, func.count()).where(Finding.template_id.isnot(None)).group_by(Finding.template_id)
    )).all())
    return [_read(t, usage.get(t.id, 0)) for t in templates]


@router.get("/export")
async def export_templates(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_scope("findings:read")),
):
    """The whole library as JSON, to back up or share with another ScanR."""
    templates = (await db.execute(select(FindingTemplate).order_by(FindingTemplate.title))).scalars().all()
    return {
        "scanr_finding_library": 1,
        "entries": [TemplateIn(**_read(t).model_dump(include=set(TemplateIn.model_fields))).model_dump() for t in templates],
    }


class LibraryImport(BaseModel):
    entries: list[TemplateIn] = Field(..., max_length=5000)
    overwrite: bool = False


@router.post("/import")
async def import_templates(
    body: LibraryImport,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:triage")),
):
    """Add entries from an export. Existing titles are skipped unless overwrite."""
    existing = {t.title.lower(): t for t in (await db.execute(select(FindingTemplate))).scalars().all()}
    added = updated = skipped = 0
    for entry in body.entries:
        current = existing.get(entry.title.strip().lower())
        if current is None:
            template = FindingTemplate(created_by=current_user.email)
            _store(template, entry)
            db.add(template)
            existing[template.title.lower()] = template
            added += 1
        elif body.overwrite:
            _store(current, entry)
            current.updated_by = current_user.email
            updated += 1
        else:
            skipped += 1
    await db.commit()
    return {"added": added, "updated": updated, "skipped": skipped}


@router.get("/{template_id}", response_model=TemplateRead)
async def get_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_scope("findings:read")),
):
    template = await db.get(FindingTemplate, template_id)
    if template is None:
        raise HTTPException(status_code=404, detail="Library entry not found")
    return _read(template)


@router.post("", response_model=TemplateRead, status_code=201)
async def create_template(
    body: TemplateIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:triage")),
):
    if await _title_taken(db, body.title):
        raise HTTPException(status_code=409, detail="A library entry with this title already exists")
    template = FindingTemplate(created_by=current_user.email)
    _store(template, body)
    db.add(template)
    await db.commit()
    await db.refresh(template)
    return _read(template)


@router.put("/{template_id}", response_model=TemplateRead)
async def update_template(
    template_id: str,
    body: TemplateIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:triage")),
):
    template = await db.get(FindingTemplate, template_id)
    if template is None:
        raise HTTPException(status_code=404, detail="Library entry not found")
    if await _title_taken(db, body.title, exclude_id=template_id):
        raise HTTPException(status_code=409, detail="A library entry with this title already exists")
    _store(template, body)
    template.updated_by = current_user.email
    await db.commit()
    await db.refresh(template)
    return _read(template)


@router.delete("/{template_id}", status_code=204)
async def delete_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_scope("findings:triage")),
):
    """Remove an entry. Findings that used it keep their text."""
    template = await db.get(FindingTemplate, template_id)
    if template is None:
        raise HTTPException(status_code=404, detail="Library entry not found")
    await db.delete(template)
    await db.commit()
