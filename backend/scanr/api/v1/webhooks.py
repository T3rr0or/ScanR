from __future__ import annotations

import ipaddress
import json
import socket
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models.base import new_uuid
from scanr.models.user import User
from scanr.models.webhook import Webhook

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

VALID_EVENTS = {
    "scan.completed",
    "scan.failed",
    "finding.critical",
    "finding.high",
    "*",
}


def _validate_webhook_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Webhook URL must use http or https")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid webhook URL")
    # Resolve all addresses (IPv4 + IPv6) and block private/internal ranges
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
                raise ValueError("Webhook URL cannot target private or internal addresses")
    except socket.gaierror:
        pass  # unresolvable hostname — allow it (will fail at dispatch time)
    except ValueError:
        raise
    return url


class WebhookCreate(BaseModel):
    name: str
    url: str
    secret: str | None = None
    events: list[str] = ["scan.completed", "finding.critical"]
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def no_ssrf(cls, v: str) -> str:
        return _validate_webhook_url(v)


class WebhookUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    secret: str | None = None
    events: list[str] | None = None
    enabled: bool | None = None

    @field_validator("url")
    @classmethod
    def no_ssrf(cls, v: str | None) -> str | None:
        if v is not None:
            return _validate_webhook_url(v)
        return v


class WebhookRead(BaseModel):
    id: str
    name: str
    url: str
    events: list[str]
    enabled: bool
    last_status: int | None
    last_triggered_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


def _to_read(w: Webhook) -> WebhookRead:
    d = WebhookRead.model_validate(w)
    d.events = json.loads(w.events) if w.events else []
    return d


@router.get("", response_model=list[WebhookRead])
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:read")),
):
    result = await db.execute(select(Webhook).where(Webhook.user_id == current_user.id))
    return [_to_read(w) for w in result.scalars().all()]


@router.post("", response_model=WebhookRead, status_code=201)
async def create_webhook(
    body: WebhookCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:write")),
):
    webhook = Webhook(
        id=new_uuid(),
        user_id=current_user.id,
        name=body.name,
        url=body.url,
        secret=body.secret,
        events=json.dumps(body.events),
        enabled=body.enabled,
    )
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)
    return _to_read(webhook)


@router.put("/{webhook_id}", response_model=WebhookRead)
async def update_webhook(
    webhook_id: str,
    body: WebhookUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:write")),
):
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id, Webhook.user_id == current_user.id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    if body.name is not None:
        webhook.name = body.name
    if body.url is not None:
        webhook.url = body.url
    if body.secret is not None:
        webhook.secret = body.secret
    if body.events is not None:
        webhook.events = json.dumps(body.events)
    if body.enabled is not None:
        webhook.enabled = body.enabled

    await db.commit()
    await db.refresh(webhook)
    return _to_read(webhook)


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:write")),
):
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id, Webhook.user_id == current_user.id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.delete(webhook)
    await db.commit()


@router.post("/{webhook_id}/test", status_code=200)
async def test_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("webhooks:write")),
):
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id, Webhook.user_id == current_user.id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    from scanr.core.webhook_dispatcher import _send
    await _send(webhook, "test", {"message": "ScanR webhook test ping"}, db)
    return {"status": "sent", "last_status": webhook.last_status}
