from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.auth import create_access_token, create_refresh_token, decode_token, verify_password
from scanr.auth.jwt_handler import create_mfa_token
from scanr.auth.mfa import verify_second_factor
from scanr.auth.password import dummy_verify, hash_password, needs_rehash
from scanr.config import get_settings
from scanr.core import audit
from scanr.db import get_db
from scanr.core.limiter import limiter
from scanr.models import User
from scanr.models.user import _MAX_FAILED_ATTEMPTS, _LOCKOUT_MINUTES
from scanr.schemas import LoginRequest, LoginResponse, MfaLoginRequest, TokenResponse

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


async def _get_pw_epoch(user_id: str) -> str | None:
    r = _get_redis()
    val = await r.get(f"{_PW_EPOCH_PREFIX}{user_id}")
    if not val:
        return None
    return val.decode() if isinstance(val, bytes) else str(val)


async def _password_generation(user: User) -> str | None:
    """Return the durable generation, falling back to pre-0025 Redis data."""
    if user.password_generation:
        return user.password_generation
    return await _get_pw_epoch(user.id)


async def _assert_not_pre_password_change(user: User, payload: dict) -> str | None:
    """Reject refresh tokens from before the user's last password change.
    Fails closed when Redis is unavailable."""
    try:
        generation = await _password_generation(user)
    except Exception:
        logger.error("Redis unavailable during refresh epoch check — failing closed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token service unavailable, please try again",
        )
    # Existing numeric Redis timestamp values are intentionally treated as
    # opaque generations. Older tokens have no claim and remain revoked during
    # rollout; the next password change moves the marker into the user row.
    if generation and payload.get("pw_generation") != generation:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired — please log in again",
        )
    return generation


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


def _as_utc(value: datetime) -> datetime:
    """Normalize datetimes returned by timezone-losing DB drivers (SQLite)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class RefreshRequest(BaseModel):
    refresh_token: str | None = None  # optional — prefer HttpOnly cookie


class LogoutRequest(BaseModel):
    refresh_token: str | None = None  # optional — prefer HttpOnly cookie


async def _record_failed_login(db: AsyncSession, user: User, now: datetime) -> None:
    """Count a failed password or second-factor attempt towards the lockout."""
    from datetime import timedelta

    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= _MAX_FAILED_ATTEMPTS:
        user.locked_until = now + timedelta(minutes=_LOCKOUT_MINUTES)
        user.failed_login_count = 0
        logger.warning("Account locked: email=%s after %d failures", user.email, _MAX_FAILED_ATTEMPTS)
    await db.commit()


def _raise_if_locked(user: User | None, now: datetime, ip: str) -> None:
    if user and user.locked_until and _as_utc(user.locked_until) > now:
        logger.warning("Locked account login attempt: email=%s ip=%s", user.email, ip)
        # Generic detail: a distinctive message would confirm the account exists.
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Please try again later.",
        )


async def _token_generation(user: User) -> str | None:
    try:
        return await _password_generation(user)
    except Exception:
        logger.error("Redis unavailable during login token issuance — failing closed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token service unavailable, please try again",
        )


async def start_session(db: AsyncSession, response: Response, user: User) -> str:
    """Finish a fully authenticated login: clear lockout state, set the refresh
    cookie and return a new access token. Shared by password, MFA and SSO."""
    if user.failed_login_count or user.locked_until:
        user.failed_login_count = 0
        user.locked_until = None
    await db.commit()
    generation = await _token_generation(user)
    _set_refresh_cookie(response, create_refresh_token(user.id, generation))
    return create_access_token(user.id, user.role)


@router.post("/login", response_model=LoginResponse, response_model_exclude_none=True)
@limiter.limit("10/minute")
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    ip = request.client.host if request.client else "unknown"

    result = await db.execute(select(User).where(User.email == body.email.lower().strip(), User.is_active == True))
    user = result.scalar_one_or_none()

    try:
        _raise_if_locked(user, now, ip)
    except HTTPException:
        await audit.record(request, "auth.login_locked", email=body.email.lower().strip(), status_code=429)
        raise

    if not user:
        # Spend the same bcrypt time as a real verify: returning early here is a
        # timing oracle that tells an attacker which emails have accounts.
        dummy_verify(body.password)

    if not user or not verify_password(body.password, user.hashed_password):
        logger.warning("Failed login attempt from ip=%s email=%s", ip, body.email)
        if user:
            await _record_failed_login(db, user, now)
        await audit.record(request, "auth.login_failed", email=body.email.lower().strip(), status_code=401,
                           details={"reason": "password"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Transparently upgrade bcrypt cost factor on successful login
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(body.password)
        await db.commit()
        logger.info("Rehashed password for user=%s (upgraded bcrypt rounds)", user.email)

    if user.totp_enabled:
        # The failure counter is deliberately left alone until the second factor
        # passes too: resetting it here would let someone holding the password
        # interleave correct passwords with unlimited code guesses.
        logger.info("Password accepted, second factor required: user=%s ip=%s", user.email, ip)
        generation = await _token_generation(user)
        return LoginResponse(mfa_required=True, mfa_token=create_mfa_token(user.id, generation))

    logger.info("Successful login: user=%s ip=%s", user.email, ip)
    await audit.record(request, "auth.login", user=user, status_code=200, details={"method": "password"})
    return LoginResponse(access_token=await start_session(db, response, user))


@router.post("/login/mfa", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_mfa(
    request: Request,
    response: Response,
    body: MfaLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    ip = request.client.host if request.client else "unknown"
    expired = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sign-in expired — enter your password again",
    )
    try:
        payload = decode_token(body.mfa_token)
    except ValueError:
        raise expired
    if payload.get("type") != "mfa" or not payload.get("jti"):
        raise expired

    result = await db.execute(select(User).where(User.id == payload.get("sub"), User.is_active == True))
    user = result.scalar_one_or_none()
    if not user or not user.totp_enabled:
        raise expired
    _raise_if_locked(user, now, ip)
    # A password change since the challenge was issued invalidates it.
    generation = await _token_generation(user)
    if generation and payload.get("pw_generation") != generation:
        raise expired

    if not await verify_second_factor(db, user, body.code):
        logger.warning("Failed second factor from ip=%s email=%s", ip, user.email)
        await _record_failed_login(db, user, now)
        await audit.record(request, "auth.login_failed", email=user.email, status_code=401,
                           details={"reason": "second factor"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication code")

    # One challenge, one session: a captured challenge plus a later code must
    # not mint a second session.
    try:
        claimed = await _claim_jti(payload["jti"], payload["exp"])
    except Exception:
        logger.error("Redis unavailable during MFA login — failing closed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token service unavailable, please try again",
        )
    if not claimed:
        raise expired

    logger.info("Successful login with second factor: user=%s ip=%s", user.email, ip)
    await audit.record(request, "auth.login", user=user, status_code=200, details={"method": "password+totp"})
    return TokenResponse(access_token=await start_session(db, response, user))


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

    generation = await _assert_not_pre_password_change(user, payload)

    new_refresh = create_refresh_token(user.id, generation)
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
