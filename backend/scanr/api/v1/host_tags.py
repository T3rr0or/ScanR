from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, ForeignKey, DateTime, func, UniqueConstraint

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models.base import Base, new_uuid
from scanr.models.user import User


# Inline model — no separate file needed for a simple pivot table
class HostTag(Base):
    __tablename__ = "host_tags"
    __table_args__ = (UniqueConstraint("user_id", "ip", "tag", name="uq_host_tags"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    tag: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())


router = APIRouter(prefix="/host-tags", tags=["host-tags"])


@router.get("")
async def list_tags(
    ip: str = Query(..., description="Host IP address"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all tags for a given IP."""
    result = await db.execute(
        select(HostTag.tag).where(HostTag.user_id == current_user.id, HostTag.ip == ip).order_by(HostTag.tag)
    )
    return [r[0] for r in result.all()]


@router.get("/all")
async def all_tags(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return all {ip: [tags]} for the current user — used to populate filter dropdowns."""
    result = await db.execute(
        select(HostTag.ip, HostTag.tag)
        .where(HostTag.user_id == current_user.id)
        .order_by(HostTag.ip, HostTag.tag)
    )
    out: dict[str, list[str]] = {}
    for ip, tag in result.all():
        out.setdefault(ip, []).append(tag)
    return out


@router.post("", status_code=201)
async def add_tag(
    ip: str = Query(...),
    tag: str = Query(..., min_length=1, max_length=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Add a tag to a host IP. Idempotent — duplicate tags are silently ignored."""
    tag = tag.strip().lower()
    if not tag:
        raise HTTPException(status_code=400, detail="Tag cannot be empty")
    existing = await db.execute(
        select(HostTag).where(HostTag.user_id == current_user.id, HostTag.ip == ip, HostTag.tag == tag)
    )
    if not existing.scalar_one_or_none():
        db.add(HostTag(id=new_uuid(), user_id=current_user.id, ip=ip, tag=tag))
        await db.commit()
    return {"ip": ip, "tag": tag}


@router.delete("", status_code=204)
async def remove_tag(
    ip: str = Query(...),
    tag: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove a tag from a host IP."""
    await db.execute(
        delete(HostTag).where(HostTag.user_id == current_user.id, HostTag.ip == ip, HostTag.tag == tag.strip().lower())
    )
    await db.commit()
