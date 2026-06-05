from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.auth.password import hash_password, verify_password
from scanr.db import get_db
from scanr.deps import get_current_user, require_admin
from scanr.models.base import new_uuid
from scanr.models.user import User, UserRole
from scanr.schemas.user import UserRead

router = APIRouter(prefix="/users", tags=["users"])
logger = logging.getLogger(__name__)


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, max_length=255)
    email: str | None = Field(None, max_length=255)


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=10)


class AdminUserCreate(BaseModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=10)
    full_name: str | None = Field(None, max_length=255)
    role: UserRole = UserRole.analyst


class AdminUserUpdate(BaseModel):
    full_name: str | None = Field(None, max_length=255)
    email: str | None = Field(None, max_length=255)
    role: UserRole | None = None
    is_active: bool | None = None


# ── Own profile ───────────────────────────────────────────────────────────────

@router.get("/me", response_model=UserRead)
async def get_profile(current_user: User = Depends(get_current_user)):
    return current_user


@router.patch("/me", response_model=UserRead)
async def update_profile(
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if body.email and body.email != current_user.email:
        existing = await db.execute(select(User).where(User.email == body.email.lower().strip()))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already in use")
        current_user.email = body.email.lower().strip()
    if body.full_name is not None:
        current_user.full_name = body.full_name
    await db.commit()
    await db.refresh(current_user)
    return current_user


@router.post("/me/change-password", status_code=204)
async def change_password(
    body: PasswordChange,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    current_user.hashed_password = hash_password(body.new_password)
    await db.commit()
    logger.info("Password changed for user=%s", current_user.email)


# ── Admin user management ─────────────────────────────────────────────────────

@router.get("", response_model=list[UserRead])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    result = await db.execute(select(User).order_by(User.email))
    return result.scalars().all()


@router.post("", response_model=UserRead, status_code=201)
async def create_user(
    body: AdminUserCreate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    email = body.email.lower().strip()
    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(
        id=new_uuid(),
        email=email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
        role=body.role,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("Admin created user=%s role=%s", user.email, user.role)
    return user


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: str,
    body: AdminUserUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and body.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    if body.email and body.email != user.email:
        existing = await db.execute(select(User).where(User.email == body.email.lower().strip()))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = body.email.lower().strip()
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    user.is_active = False  # soft-delete — preserve scan history
    await db.commit()
