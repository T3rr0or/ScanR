from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.auth import create_access_token, create_refresh_token, decode_token, verify_password
from scanr.auth.password import hash_password, needs_rehash
from scanr.config import get_settings
from scanr.db import get_db
from scanr.core.limiter import limiter
from scanr.models import User
from scanr.models.user import _MAX_FAILED_ATTEMPTS, _LOCKOUT_MINUTES
from scanr.schemas import LoginRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)
settings = get_settings()

_REVOKE_PREFIX = "scanr:revoked_jti:"
_PW_EPOCH_PREFIX = "scanr:pw_epoch:"
_COOKIE_NAME = "scanr_rt"
_COOKIE_PATH = "/api/v1/auth"


def _get_redis():
    from scanr.db.redis import get_redis
    return get_redis()


async def _revoke_jti(jti: str, exp: int) -> None:
    """Best-effort JTI revocation, used on logout. The refresh rotation path
    uses _claim_jti instead (atomic check-and-set, fails closed)."""
    ttl = max(1, exp - int(datetime.now(timezone.utc).timestamp()))
    try:
        r = _get_redis()
        await r.set(f"{_REVOKE_PREFIX}{jti}", "1", ex=ttl)
    except Exception:
        logger.warning("Redis unavailable — could not revoke refresh token JTI on logout")


async def _claim_jti(jti: str, exp: int) -> bool:
    """Atomically mark a refresh-token JTI as used. Returns False if it was
    already claimed. SET NX makes check-and-set a single operation, so two
    concurrent /refresh calls with the same token cannot both succeed.
    Raises on Redis failure so the caller can fail closed."""
    ttl = max(1, exp - int(datetime.now(timezone.utc).timestamp()))
    r = _get_redis()
    return bool(await r.set(f"{_REVOKE_PREFIX}{jti}", "1", ex=ttl, nx=True))


async def _bump_pw_epoch(user_id: str) -> None:
    """Invalidate every refresh token issued before now for a user.
    Called on password change. Raises on Redis failure so the caller can
    abort rather than leave stale tokens valid."""
    now_ts = int(datetime.now(timezone.utc).timestamp())
    r = _get_redis()
    # The key only needs to outlive the longest-lived outstanding refresh token.
    await r.set(
        f"{_PW_EPOCH_PREFIX}{user_id}",
        str(now_ts),
        ex=settings.refresh_token_expire_days * 86400 + 60,
    )


async def _get_pw_epoch(user_id: str) -> int:
    r = _get_redis()
    val = await r.get(f"{_PW_EPOCH_PREFIX}{user_id}")
    return int(val) if val else 0


async def _assert_not_pre_password_change(user_id: str, payload: dict) -> None:
    """Reject refresh tokens issued before the user's last password change.
    Fails closed when Redis is unavailable."""
    try:
        epoch = await _get_pw_epoch(user_id)
    except Exception:
        logger.error("Redis unavailable during refresh epoch check — failing closed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token service unavailable, please try again",
        )
    # Refresh tokens carry no iat claim; derive issue time from exp minus the
    # configured lifetime.
    issued_at = int(payload["exp"]) - settings.refresh_token_expire_days * 86400
    if epoch and issued_at < epoch:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired — please log in again",
        )


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        samesite="strict",
        secure=settings.secure_cookies,
        path=_COOKIE_PATH,
        max_age=settings.refresh_token_expire_days * 86400,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=_COOKIE_NAME, path=_COOKIE_PATH)


class RefreshRequest(BaseModel):
    refresh_token: str | None = None  # optional — prefer HttpOnly cookie


class LogoutRequest(BaseModel):
    refresh_token: str | None = None  # optional — prefer HttpOnly cookie


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    ip = request.client.host if request.client else "unknown"

    result = await db.execute(select(User).where(User.email == body.email.lower().strip(), User.is_active == True))
    user = result.scalar_one_or_none()

    if user and user.locked_until and user.locked_until > now:
        logger.warning("Locked account login attempt: email=%s ip=%s", body.email, ip)
        # Generic detail: a distinctive message would confirm the account exists.
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Please try again later.",
        )

    if not user or not verify_password(body.password, user.hashed_password):
        logger.warning("Failed login attempt from ip=%s email=%s", ip, body.email)
        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= _MAX_FAILED_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=_LOCKOUT_MINUTES)
                user.failed_login_count = 0
                logger.warning("Account locked: email=%s after %d failures", body.email, _MAX_FAILED_ATTEMPTS)
            await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    needs_update = bool(user.failed_login_count or user.locked_until)
    if user.failed_login_count:
        user.failed_login_count = 0
    if user.locked_until:
        user.locked_until = None

    # Transparently upgrade bcrypt cost factor on successful login
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(body.password)
        needs_update = True
        logger.info("Rehashed password for user=%s (upgraded bcrypt rounds)", user.email)

    if needs_update:
        await db.commit()

    logger.info("Successful login: user=%s ip=%s", user.email, ip)
    refresh_token = create_refresh_token(user.id)
    _set_refresh_cookie(response, refresh_token)
    return TokenResponse(access_token=create_access_token(user.id, user.role))


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
async def refresh(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    scanr_rt: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
):
    # Cookie takes priority; fall back to JSON body for non-browser API clients
    raw_token = scanr_rt or (body.refresh_token if body else None)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token")

    try:
        payload = decode_token(raw_token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a refresh token")

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Atomically claim the JTI: first use wins, reuse is rejected. Fails closed
    # when Redis is unavailable rather than allowing unrevoked rotation.
    try:
        claimed = await _claim_jti(jti, payload["exp"])
    except Exception:
        logger.error("Redis unavailable during refresh — failing closed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token service unavailable, please try again",
        )
    if not claimed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token already used or revoked")

    result = await db.execute(select(User).where(User.id == payload["sub"], User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    await _assert_not_pre_password_change(user.id, payload)

    new_refresh = create_refresh_token(user.id)
    _set_refresh_cookie(response, new_refresh)
    return TokenResponse(access_token=create_access_token(user.id, user.role))


@router.post("/logout", status_code=204)
async def logout(
    response: Response,
    body: LogoutRequest | None = None,
    scanr_rt: str | None = Cookie(default=None),
):
    raw_token = scanr_rt or (body.refresh_token if body else None)
    _clear_refresh_cookie(response)

    if raw_token:
        try:
            payload = decode_token(raw_token)
            if payload.get("type") == "refresh":
                jti = payload.get("jti")
                if jti:
                    await _revoke_jti(jti, payload["exp"])
        except ValueError:
            pass
