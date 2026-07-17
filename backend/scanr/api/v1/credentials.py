from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.credentials.vault import encrypt
from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Credential
from scanr.models.base import new_uuid
from scanr.models.user import User
from scanr.schemas import CredentialCreate, CredentialRead

router = APIRouter(prefix="/credentials", tags=["credentials"])


@router.get("", response_model=list[CredentialRead])
async def list_credentials(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("credentials:read")),
):
    result = await db.execute(
        select(Credential)
        .where(Credential.user_id == current_user.id)
        .order_by(Credential.name)
    )
    return result.scalars().all()


@router.post("", response_model=CredentialRead, status_code=status.HTTP_201_CREATED)
async def create_credential(
    body: CredentialCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("credentials:write")),
):
    # Enforce per-user unique name
    existing = await db.execute(
        select(Credential).where(Credential.user_id == current_user.id, Credential.name == body.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Credential named '{body.name}' already exists")

    cred = Credential(
        id=new_uuid(),
        user_id=current_user.id,
        name=body.name,
        type=body.type,
        username=body.username,
        description=body.description,
        encrypted_data=encrypt(body.secret_data),
    )
    db.add(cred)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=409, detail=f"Credential named '{body.name}' already exists")
    await db.refresh(cred)
    return cred


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    credential_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("credentials:write")),
):
    result = await db.execute(
        select(Credential).where(
            Credential.id == credential_id,
            Credential.user_id == current_user.id,
        )
    )
    cred = result.scalar_one_or_none()
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    await db.delete(cred)
    await db.commit()
