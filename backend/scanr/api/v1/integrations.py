"""External ticketing integrations (TOPdesk).

Configuration is admin-only and the application password is never returned.
Creating a ticket needs findings:triage rather than findings:read — it writes to
a system outside ScanR, on the customer's service desk.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import require_admin, require_scope
from scanr.integrations import topdesk
from scanr.models import Finding, Host, Scan, TicketLink
from scanr.models.user import User
from scanr.utils.exceptions import VaultError

router = APIRouter(prefix="/integrations", tags=["integrations"])
logger = logging.getLogger(__name__)


class TopdeskConfigBody(BaseModel):
    url: str = Field(max_length=2048)
    username: str = Field(max_length=255)
    # Omit to keep the stored password — lets an operator edit the URL without
    # re-entering the secret, and means the UI never has to hold it.
    password: str | None = Field(default=None, max_length=512)
    defaults: dict = Field(default_factory=dict)


@router.get("/topdesk")
async def get_topdesk_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    return await topdesk.config_status(db)


@router.put("/topdesk", status_code=204)
async def set_topdesk_config(
    body: TopdeskConfigBody,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    status = await topdesk.config_status(db)
    if not body.password and not status["has_password"]:
        raise HTTPException(
            status_code=400,
            detail="An application password is required the first time TOPdesk is configured.",
        )
    try:
        await topdesk.save_config(
            db, url=body.url, username=body.username,
            password=body.password, defaults=body.defaults,
        )
    except topdesk.TopdeskError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except VaultError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot store the TOPdesk password — VAULT_KEY is required: {exc}",
        )
    logger.info("TOPdesk integration configured by %s", current_user.email)


@router.delete("/topdesk", status_code=204)
async def delete_topdesk_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    await topdesk.clear_config(db)
    logger.info("TOPdesk integration cleared by %s", current_user.email)


@router.post("/topdesk/test")
async def test_topdesk_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Make one authenticated call, so setup is confirmed here rather than
    discovered the first time someone tries to file a ticket."""
    config = await topdesk.load_config(db)
    if config is None:
        raise HTTPException(status_code=400, detail="TOPdesk is not configured.")
    try:
        return await topdesk.TopdeskClient(config).verify()
    except topdesk.TopdeskError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# ── per-finding tickets ──────────────────────────────────────────────────────

def _link_read(link: TicketLink) -> dict:
    return {
        "id": link.id,
        "finding_id": link.finding_id,
        "provider": link.provider,
        "external_id": link.external_id,
        "external_key": link.external_key,
        "url": link.url,
        "external_status": link.external_status,
        "created_at": link.created_at,
    }


async def _own_finding_with_host(finding_id: str, user_id: str, db: AsyncSession):
    row = (
        await db.execute(
            select(Finding, Host.ip)
            .outerjoin(Host, Finding.host_id == Host.id)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Finding.id == finding_id, Scan.user_id == user_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding, host_ip = row
    return finding, host_ip or ""


@router.post("/topdesk/findings/{finding_id}/ticket", status_code=201)
async def create_topdesk_ticket(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:triage")),
):
    """Create — or adopt — the TOPdesk incident for this finding."""
    finding, host_ip = await _own_finding_with_host(finding_id, current_user.id, db)
    try:
        link, created = await topdesk.create_ticket_for_finding(
            db, finding, host_ip, user_id=current_user.id
        )
    except topdesk.TopdeskError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {**_link_read(link), "created": created}


@router.get("/topdesk/findings/{finding_id}/ticket")
async def get_topdesk_ticket(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    await _own_finding_with_host(finding_id, current_user.id, db)
    link = (
        await db.execute(
            select(TicketLink).where(
                TicketLink.finding_id == finding_id,
                TicketLink.provider == topdesk.PROVIDER,
            )
        )
    ).scalar_one_or_none()
    if link is None:
        raise HTTPException(status_code=404, detail="No TOPdesk ticket for this finding")
    return _link_read(link)
