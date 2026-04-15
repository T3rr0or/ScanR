"""
Scan agent management endpoints.
Users register agents, receive a one-time token, then run the agent CLI on their internal network.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models.base import new_uuid
from scanr.models.scan_agent import ScanAgent
from scanr.models.user import User

router = APIRouter(prefix="/agents", tags=["agents"])


def _generate_agent_token() -> tuple[str, str, str]:
    """Returns (raw_token, hash, prefix)."""
    raw = "sk_agent_" + secrets.token_urlsafe(32)
    h = hashlib.sha256(raw.encode()).hexdigest()
    return raw, h, raw[:16]


class AgentCreate(BaseModel):
    name: str
    description: str | None = None


class AgentRead(BaseModel):
    id: str
    name: str
    description: str | None
    prefix: str
    enabled: bool
    last_seen_at: datetime | None
    ip_address: str | None
    agent_version: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AgentCreated(AgentRead):
    token: str  # shown once


@router.get("", response_model=list[AgentRead])
async def list_agents(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanAgent)
        .where(ScanAgent.user_id == current_user.id, ScanAgent.enabled == True)
        .order_by(ScanAgent.name)
    )
    return result.scalars().all()


@router.post("", response_model=AgentCreated, status_code=201)
async def register_agent(
    body: AgentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    raw, token_hash, prefix = _generate_agent_token()
    agent = ScanAgent(
        id=new_uuid(),
        user_id=current_user.id,
        name=body.name,
        description=body.description,
        token_hash=token_hash,
        prefix=prefix,
        enabled=True,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    out = AgentCreated.model_validate(agent)
    out.token = raw
    return out


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanAgent).where(ScanAgent.id == agent_id, ScanAgent.user_id == current_user.id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.enabled = False  # soft-delete
    await db.commit()
