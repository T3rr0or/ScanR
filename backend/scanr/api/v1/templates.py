from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models.base import new_uuid
from scanr.models.scan_template import ScanTemplate
from scanr.models.user import User

router = APIRouter(prefix="/templates", tags=["templates"])


class TemplateCreate(BaseModel):
    name: str
    description: str | None = None
    profile_json: dict | None = None


class TemplateUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    profile_json: dict | None = None


class TemplateRead(BaseModel):
    id: str
    name: str
    description: str | None
    profile_json: dict | None = None
    is_system: bool
    user_id: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


def _to_read(t: ScanTemplate) -> TemplateRead:
    return TemplateRead(
        id=t.id,
        name=t.name,
        description=t.description,
        profile_json=json.loads(t.profile_json) if t.profile_json else None,
        is_system=t.is_system,
        user_id=t.user_id,
        created_at=t.created_at,
    )


@router.get("", response_model=list[TemplateRead])
async def list_templates(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanTemplate).where(
            or_(ScanTemplate.is_system == True, ScanTemplate.user_id == current_user.id)
        ).order_by(ScanTemplate.is_system.desc(), ScanTemplate.name)
    )
    return [_to_read(t) for t in result.scalars().all()]


@router.post("", response_model=TemplateRead, status_code=201)
async def create_template(
    body: TemplateCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    template = ScanTemplate(
        id=new_uuid(),
        user_id=current_user.id,
        name=body.name,
        description=body.description,
        profile_json=json.dumps(body.profile_json) if body.profile_json else None,
        is_system=False,
    )
    db.add(template)
    await db.commit()
    await db.refresh(template)
    return _to_read(template)


@router.get("/{template_id}", response_model=TemplateRead)
async def get_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanTemplate).where(
            ScanTemplate.id == template_id,
            or_(ScanTemplate.is_system == True, ScanTemplate.user_id == current_user.id),
        )
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    return _to_read(t)


@router.put("/{template_id}", response_model=TemplateRead)
async def update_template(
    template_id: str,
    body: TemplateUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id, ScanTemplate.user_id == current_user.id)
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found or not editable")
    if t.is_system:
        raise HTTPException(status_code=403, detail="Cannot modify system templates")

    if body.name is not None:
        t.name = body.name
    if body.description is not None:
        t.description = body.description
    if body.profile_json is not None:
        t.profile_json = json.dumps(body.profile_json)

    await db.commit()
    await db.refresh(t)
    return _to_read(t)


@router.delete("/{template_id}", status_code=204)
async def delete_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.id == template_id, ScanTemplate.user_id == current_user.id)
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    if t.is_system:
        raise HTTPException(status_code=403, detail="Cannot delete system templates")
    await db.delete(t)
    await db.commit()
