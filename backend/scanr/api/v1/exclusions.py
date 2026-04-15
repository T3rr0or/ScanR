from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models.base import new_uuid
from scanr.models.exclusion import Exclusion
from scanr.models.scan import Scan
from scanr.models.user import User

router = APIRouter(prefix="/scans/{scan_id}/exclusions", tags=["exclusions"])

VALID_TYPES = {"ip", "cidr", "port", "host"}


class ExclusionCreate(BaseModel):
    type: str
    value: str
    reason: str | None = None


class ExclusionRead(BaseModel):
    id: str
    scan_id: str
    type: str
    value: str
    reason: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


async def _own_scan(scan_id: str, user_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("", response_model=list[ExclusionRead])
async def list_exclusions(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _own_scan(scan_id, current_user.id, db)
    result = await db.execute(select(Exclusion).where(Exclusion.scan_id == scan_id))
    return result.scalars().all()


@router.post("", response_model=ExclusionRead, status_code=201)
async def create_exclusion(
    scan_id: str,
    body: ExclusionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    await _own_scan(scan_id, current_user.id, db)

    if body.type not in VALID_TYPES:  # type: ignore[operator]
        raise HTTPException(status_code=422, detail=f"type must be one of: {', '.join(VALID_TYPES)}")

    excl = Exclusion(
        id=new_uuid(),
        scan_id=scan_id,
        type=body.type,
        value=body.value,
        reason=body.reason,
    )
    db.add(excl)
    await db.commit()
    await db.refresh(excl)
    return excl


@router.delete("/{excl_id}", status_code=204)
async def delete_exclusion(
    scan_id: str,
    excl_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Exclusion).where(Exclusion.id == excl_id, Exclusion.scan_id == scan_id))
    excl = result.scalar_one_or_none()
    if not excl:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    await db.delete(excl)
    await db.commit()
