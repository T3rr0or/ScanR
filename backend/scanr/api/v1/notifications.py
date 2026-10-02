"""Notification channels: email, Teams and Slack scan summaries.

Reuses the webhooks scopes: both deliver scan events off the box, and an API
key allowed to configure one should be allowed to configure the other.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.core import notifications
from scanr.core.limiter import limiter
from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models.base import new_uuid
from scanr.models.notification_channel import NotificationChannel
from scanr.models.user import User

router = APIRouter(prefix="/notifications", tags=["notifications"])

Kind = Literal["email", "slack", "teams"]
Event = Literal["scan.completed", "scan.failed"]


class ChannelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    kind: Kind
    target: str = Field(..., min_length=3, max_length=2048)
    events: list[Event] = Field(default_factory=lambda: ["scan.completed", "scan.failed"], min_length=1)
    min_priority: float | None = Field(None, ge=0, le=100)
    enabled: bool = True

    @field_validator("events")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        return sorted(set(v))


class ChannelUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    target: str | None = Field(None, min_length=3, max_length=2048)
    events: list[Event] | None = Field(None, min_length=1)
    min_priority: float | None = Field(None, ge=0, le=100)
    # Distinguishes "set min_priority to null" from "leave it alone".
    clear_min_priority: bool = False
    enabled: bool | None = None


class ChannelRead(BaseModel):
    id: str
    name: str
    kind: str
    target: str  # email address, or only the host of a webhook URL
    events: list[str]
    min_priority: float | None
    enabled: bool
    last_status: str | None
    last_error: str | None
    last_sent_at: datetime | None
    created_at: datetime


class NotificationConfig(BaseModel):
    email_enabled: bool


def _read(channel: NotificationChannel) -> ChannelRead:
    return ChannelRead(
        id=channel.id,
        name=channel.name,
        kind=channel.kind,
        target=notifications.display_target(channel),
        events=json.loads(channel.events),
        min_priority=channel.min_priority,
        enabled=channel.enabled,
        last_status=channel.last_status,
        last_error=channel.last_error,
        last_sent_at=channel.last_sent_at,
        created_at=channel.created_at,
    )


def _checked_target(kind: str, target: str) -> str:
    try:
        clean = notifications.validate_target(kind, target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if kind == "email" and not get_settings().smtp_enabled:
        raise HTTPException(
            status_code=400,
            detail="Email is not configured on this server. Ask an administrator to set SMTP_HOST and SMTP_FROM.",
        )
    try:
        return notifications.encrypt_target(kind, clean)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Encryption is unavailable; verify VAULT_KEY") from exc


async def _owned(db: AsyncSession, channel_id: str, user: User) -> NotificationChannel:
    channel = (await db.execute(
        select(NotificationChannel).where(NotificationChannel.id == channel_id, NotificationChannel.user_id == user.id)
    )).scalar_one_or_none()
    if channel is None:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    return channel


@router.get("/config", response_model=NotificationConfig)
async def notification_config(_user: User = Depends(require_scope("webhooks:read"))):
    return NotificationConfig(email_enabled=get_settings().smtp_enabled)


@router.get("", response_model=list[ChannelRead])
async def list_channels(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:read")),
):
    rows = await db.execute(
        select(NotificationChannel)
        .where(NotificationChannel.user_id == current_user.id)
        .order_by(NotificationChannel.created_at)
    )
    return [_read(c) for c in rows.scalars().all()]


@router.post("", response_model=ChannelRead, status_code=201)
async def create_channel(
    body: ChannelCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:write")),
):
    channel = NotificationChannel(
        id=new_uuid(),
        user_id=current_user.id,
        name=body.name,
        kind=body.kind,
        target=_checked_target(body.kind, body.target),
        events=json.dumps(body.events),
        min_priority=body.min_priority,
        enabled=body.enabled,
    )
    db.add(channel)
    await db.commit()
    await db.refresh(channel)
    return _read(channel)


@router.patch("/{channel_id}", response_model=ChannelRead)
async def update_channel(
    channel_id: str,
    body: ChannelUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:write")),
):
    channel = await _owned(db, channel_id, current_user)
    if body.name is not None:
        channel.name = body.name
    if body.target is not None:
        channel.target = _checked_target(channel.kind, body.target)
    if body.events is not None:
        channel.events = json.dumps(sorted(set(body.events)))
    if body.clear_min_priority:
        channel.min_priority = None
    elif body.min_priority is not None:
        channel.min_priority = body.min_priority
    if body.enabled is not None:
        channel.enabled = body.enabled
    await db.commit()
    await db.refresh(channel)
    return _read(channel)


@router.delete("/{channel_id}", status_code=204)
async def delete_channel(
    channel_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:write")),
):
    channel = await _owned(db, channel_id, current_user)
    await db.delete(channel)
    await db.commit()


@router.post("/{channel_id}/test", response_model=ChannelRead)
@limiter.limit("10/minute")
async def test_channel(
    request: Request,
    channel_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:write")),
):
    """Send an example summary now and report whether it was accepted."""
    channel = await _owned(db, channel_id, current_user)
    await notifications.deliver(db, channel, notifications.sample_summary())
    await db.commit()
    await db.refresh(channel)
    return _read(channel)
