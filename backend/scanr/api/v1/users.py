from __future__ import annotations

import json
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import AfterValidator, BaseModel, Field
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.auth.password import (
    MAX_PASSWORD_BYTES,
    hash_password,
    password_within_bcrypt_limit,
    verify_password,
)
from scanr.auth import totp
from scanr.auth.mfa import decrypt_secret, encrypt_secret, recovery_hashes, verify_second_factor
from scanr.core.limiter import limiter
from scanr.db import get_db
from scanr.deps import get_current_user, require_admin_scope, require_session_user
from scanr.models.base import new_uuid
from scanr.models.user import User, UserRole
from scanr.schemas.user import UserRead

router = APIRouter(prefix="/users", tags=["users"])
logger = logging.getLogger(__name__)


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, max_length=255)
    email: str | None = Field(None, max_length=255)


def _within_bcrypt_limit(v: str) -> str:
    # Enforced here, not via Field(max_length=...), because bcrypt's ceiling is
    # 72 *bytes* and max_length counts characters — a short multi-byte passphrase
    # can pass the character check and still blow the byte limit.
    if not password_within_bcrypt_limit(v):
        raise ValueError(f"password must be at most {MAX_PASSWORD_BYTES} bytes when UTF-8 encoded")
    return v


#: A password bcrypt can actually hash. Without the upper bound a long
#: passphrase reaches bcrypt, which raises, surfacing as a 500.
BcryptPassword = Annotated[str, Field(min_length=10), AfterValidator(_within_bcrypt_limit)]


class PasswordChange(BaseModel):
    current_password: str
    new_password: BcryptPassword


class AdminUserCreate(BaseModel):
    email: str = Field(..., max_length=255)
    password: BcryptPassword
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
    current_user: User = Depends(require_session_user),
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
# Verifying current_password makes this a password oracle. Without a limit, a
# stolen access token could brute-force it here: the account lockout only counts
# failures on /auth/login, so attempts against this endpoint are otherwise free.
@limiter.limit("5/minute")
async def change_password(
    request: Request,
    body: PasswordChange,
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_session_user),
):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    from scanr.auth import create_refresh_token

    # Hash first. Revoking sessions before the new hash exists means any failure
    # here logs the user out of every device while leaving the OLD password
    # valid — the worst of both outcomes. Hashing is pure, so on failure the
    # account is left exactly as it was.
    new_hash = hash_password(body.new_password)

    # The password and its session generation are one database transaction.
    # A concurrent login sees either the old pair or the new pair, never an old
    # password paired with the new generation.
    generation = str(uuid.uuid4())
    current_user.hashed_password = new_hash
    current_user.password_generation = generation
    await db.commit()

    # Keep the current session alive with a token carrying the new generation;
    # every other outstanding refresh token now has a stale generation.
    from scanr.api.v1 import auth as auth_api
    auth_api._set_refresh_cookie(
        response, create_refresh_token(current_user.id, generation)
    )
    logger.info("Password changed for user=%s — existing refresh tokens revoked", current_user.email)


# ── Two-factor authentication ────────────────────────────────────────────────

class MfaStatus(BaseModel):
    enabled: bool
    recovery_codes_remaining: int


class MfaSetupRequest(BaseModel):
    password: str


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaCodeRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=32)


class MfaDisableRequest(BaseModel):
    password: str
    code: str = Field(..., min_length=6, max_length=32)


class MfaRecoveryCodes(BaseModel):
    recovery_codes: list[str]


def _issue_recovery_codes(user: User) -> list[str]:
    codes = totp.generate_recovery_codes()
    user.totp_recovery_codes = json.dumps([totp.hash_recovery_code(c) for c in codes])
    return codes


def _vault_unavailable(exc: Exception) -> HTTPException:
    logger.error("Two-factor secret could not be stored or read: %s", exc)
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Two-factor authentication needs a valid VAULT_KEY on the server",
    )


@router.get("/me/mfa", response_model=MfaStatus)
async def mfa_status(current_user: User = Depends(require_session_user)):
    return MfaStatus(
        enabled=current_user.totp_enabled,
        recovery_codes_remaining=len(recovery_hashes(current_user)) if current_user.totp_enabled else 0,
    )


@router.post("/me/mfa/setup", response_model=MfaSetupResponse)
# Verifies the password, so it is an oracle like change-password.
@limiter.limit("5/minute")
async def mfa_setup(
    request: Request,
    body: MfaSetupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_session_user),
):
    """Start enrolment. Nothing is enforced until /me/mfa/enable confirms a code."""
    if current_user.totp_enabled:
        raise HTTPException(status_code=409, detail="Two-factor authentication is already enabled")
    if not verify_password(body.password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is incorrect")
    secret = totp.generate_secret()
    try:
        current_user.totp_secret = encrypt_secret(secret)
    except Exception as exc:
        raise _vault_unavailable(exc) from exc
    current_user.totp_last_step = None
    await db.commit()
    return MfaSetupResponse(secret=secret, otpauth_uri=totp.provisioning_uri(secret, current_user.email))


@router.post("/me/mfa/enable", response_model=MfaRecoveryCodes)
@limiter.limit("10/minute")
async def mfa_enable(
    request: Request,
    body: MfaCodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_session_user),
):
    """Confirm the authenticator works, turn 2FA on and return recovery codes once."""
    if current_user.totp_enabled:
        raise HTTPException(status_code=409, detail="Two-factor authentication is already enabled")
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="Start two-factor setup first")
    try:
        secret = decrypt_secret(current_user.totp_secret)
    except Exception as exc:
        raise _vault_unavailable(exc) from exc
    step = totp.verify(secret, body.code, current_user.totp_last_step)
    if step is None:
        raise HTTPException(status_code=400, detail="That code does not match. Check the time on your phone and try again.")
    current_user.totp_last_step = step
    current_user.totp_enabled = True
    codes = _issue_recovery_codes(current_user)
    await db.commit()
    logger.info("Two-factor authentication enabled for user=%s", current_user.email)
    return MfaRecoveryCodes(recovery_codes=codes)


@router.post("/me/mfa/recovery-codes", response_model=MfaRecoveryCodes)
@limiter.limit("5/minute")
async def mfa_regenerate_recovery_codes(
    request: Request,
    body: MfaCodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_session_user),
):
    """Replace every recovery code. Requires a current second factor."""
    if not current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="Two-factor authentication is not enabled")
    if not await verify_second_factor(db, current_user, body.code):
        raise HTTPException(status_code=400, detail="Invalid authentication code")
    codes = _issue_recovery_codes(current_user)
    await db.commit()
    logger.info("Recovery codes regenerated for user=%s", current_user.email)
    return MfaRecoveryCodes(recovery_codes=codes)


def _clear_mfa(user: User) -> None:
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_last_step = None
    user.totp_recovery_codes = None


@router.post("/me/mfa/disable", status_code=204)
@limiter.limit("5/minute")
async def mfa_disable(
    request: Request,
    body: MfaDisableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_session_user),
):
    """Turn 2FA off. Requires both the password and a current second factor, so
    a stolen browser session alone cannot remove it."""
    if not current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="Two-factor authentication is not enabled")
    if not verify_password(body.password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is incorrect")
    if not await verify_second_factor(db, current_user, body.code):
        raise HTTPException(status_code=400, detail="Invalid authentication code")
    _clear_mfa(current_user)
    await db.commit()
    logger.info("Two-factor authentication disabled for user=%s", current_user.email)


# ── Admin user management ─────────────────────────────────────────────────────

@router.get("", response_model=list[UserRead])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_scope("users:manage")),
):
    result = await db.execute(select(User).order_by(User.email))
    return result.scalars().all()


@router.post("", response_model=UserRead, status_code=201)
async def create_user(
    body: AdminUserCreate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_scope("users:manage")),
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
    admin: User = Depends(require_admin_scope("users:manage")),
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
    admin: User = Depends(require_admin_scope("users:manage")),
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
    from scanr.models.notification_channel import NotificationChannel
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
    await db.execute(delete(NotificationChannel).where(NotificationChannel.user_id == user_id))
    await db.execute(delete(Schedule).where(Schedule.user_id == user_id))
    # Detach any scan (this user's or another's) that references one of this
    # user's scan agents before deleting the agents — Scan.agent_id is a
    # non-cascading FK, so deleting a referenced agent would otherwise raise a
    # ForeignKeyViolation on Postgres.
    await db.execute(
        update(Scan)
        .where(Scan.agent_id.in_(select(ScanAgent.id).where(ScanAgent.user_id == user_id)))
        .values(agent_id=None)
    )
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


@router.post("/{user_id}/mfa/reset", response_model=UserRead)
async def reset_user_mfa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin_scope("users:manage")),
):
    """Remove a user's second factor, e.g. after they lost their phone and
    recovery codes. They can sign in with their password and enrol again."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    _clear_mfa(user)
    await db.commit()
    await db.refresh(user)
    logger.warning("Admin %s reset two-factor authentication for user=%s", admin.email, user.email)
    return user
