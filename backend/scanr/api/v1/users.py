from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select, update
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
    from scanr.models.api_key import APIKey
    from scanr.models.credential import Credential
    from scanr.models.exclusion import Exclusion
    from scanr.models.finding import Finding
    from scanr.models.host import Host
    from scanr.models.plugin_run import PluginRun
    from scanr.models.port import Port
    from scanr.models.report import Report
    from scanr.models.scan import Scan
    from scanr.models.scan_agent import ScanAgent
    from scanr.models.scan_template import ScanTemplate
    from scanr.models.schedule import Schedule
    from scanr.models.screenshot import Screenshot
    from scanr.models.target import Target
    from scanr.models.webhook import Webhook
    from scanr.models.wordlist import Wordlist

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    # Revoke tokens and remove user-owned non-scan data.
    await db.execute(delete(APIKey).where(APIKey.user_id == user_id))
    await db.execute(delete(Webhook).where(Webhook.user_id == user_id))
    await db.execute(delete(Schedule).where(Schedule.user_id == user_id))
    await db.execute(delete(ScanAgent).where(ScanAgent.user_id == user_id))

    # Promote user-created templates/wordlists/credentials to global.
    await db.execute(update(ScanTemplate).where(ScanTemplate.user_id == user_id).values(user_id=None))
    await db.execute(update(Wordlist).where(Wordlist.user_id == user_id).values(user_id=None))
    await db.execute(update(Credential).where(Credential.user_id == user_id).values(user_id=None))

    # Delete scan data in FK-safe order. Child tables have no ondelete="CASCADE"
    # so we must clear them before deleting scans/hosts.
    scan_ids = select(Scan.id).where(Scan.user_id == user_id)
    host_ids = select(Host.id).where(Host.scan_id.in_(scan_ids))

    # NULL out nullable back-references that point at these scans.
    await db.execute(update(Finding).where(Finding.first_seen_scan_id.in_(scan_ids)).values(first_seen_scan_id=None))
    await db.execute(update(Finding).where(Finding.last_seen_scan_id.in_(scan_ids)).values(last_seen_scan_id=None))
    # NULL compare_scan_id on any scan (own or other user) that compares against these.
    await db.execute(update(Scan).where(Scan.compare_scan_id.in_(scan_ids)).values(compare_scan_id=None))

    # Delete leaf records before their parents.
    await db.execute(delete(Port).where(Port.host_id.in_(host_ids)))
    await db.execute(delete(Screenshot).where(Screenshot.scan_id.in_(scan_ids)))
    await db.execute(delete(Finding).where(Finding.scan_id.in_(scan_ids)))
    await db.execute(delete(PluginRun).where(PluginRun.scan_id.in_(scan_ids)))
    await db.execute(delete(Exclusion).where(Exclusion.scan_id.in_(scan_ids)))
    await db.execute(delete(Report).where(Report.scan_id.in_(scan_ids)))
    await db.execute(delete(Target).where(Target.scan_id.in_(scan_ids)))
    await db.execute(delete(Host).where(Host.scan_id.in_(scan_ids)))
    # ai_results and ai_agent_runs have ondelete="CASCADE" at DB level — deleted automatically.
    await db.execute(delete(Scan).where(Scan.user_id == user_id))

    await db.delete(user)
    await db.commit()
    logger.info("Admin %s permanently deleted user=%s", admin.email, user.email)
