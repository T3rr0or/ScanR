from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.auth.api_key_auth import generate_api_key
from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models.api_key import APIKey
from scanr.models.base import new_uuid
from scanr.models.user import User

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class APIKeyCreate(BaseModel):
    name: str
    scopes: list[str] = ["scans:read", "findings:read"]
    expires_at: datetime | None = None


class APIKeyRead(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: list[str]
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class APIKeyCreated(APIKeyRead):
    key: str  # raw key — shown once only


@router.get("", response_model=list[APIKeyRead])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(APIKey).where(APIKey.user_id == current_user.id, APIKey.revoked == False)
    )
    keys = result.scalars().all()
    out = []
    for k in keys:
        d = APIKeyRead.model_construct(
            id=k.id,
            name=k.name,
            prefix=k.prefix,
            scopes=json.loads(k.scopes) if k.scopes else [],
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
            revoked=k.revoked,
            created_at=k.created_at,
        )
        out.append(d)
    return out


@router.post("", response_model=APIKeyCreated, status_code=201)
async def create_api_key(
    body: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    raw, key_hash, prefix = generate_api_key()
    api_key = APIKey(
        id=new_uuid(),
        user_id=current_user.id,
        name=body.name,
        key_hash=key_hash,
        prefix=prefix,
        scopes=json.dumps(body.scopes),
        expires_at=body.expires_at,
        revoked=False,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    out = APIKeyCreated.model_construct(
        id=api_key.id,
        name=api_key.name,
        prefix=api_key.prefix,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        revoked=api_key.revoked,
        created_at=api_key.created_at,
        scopes=body.scopes,
        key=raw,
    )
    return out


@router.delete("/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(APIKey).where(APIKey.id == key_id, APIKey.user_id == current_user.id))
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    api_key.revoked = True
    await db.commit()
