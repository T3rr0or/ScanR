"""Browser endpoints for single sign-on. See scanr/auth/oidc.py."""
from __future__ import annotations

import json
import logging
import secrets

from fastapi import APIRouter, Cookie, Depends, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.api.v1 import auth as auth_api
from scanr.auth import oidc
from scanr.auth.password import hash_password
from scanr.config import get_settings
from scanr.core import audit
from scanr.core.limiter import limiter
from scanr.db import get_db
from scanr.models.base import new_uuid
from scanr.models.user import User

router = APIRouter(prefix="/auth/oidc", tags=["auth"])
logger = logging.getLogger(__name__)

_STATE_PREFIX = "scanr:oidc_state:"
_STATE_COOKIE = "scanr_oidc_state"
_STATE_COOKIE_PATH = "/api/v1/auth/oidc"
_STATE_SECONDS = 600


class OIDCConfig(BaseModel):
    enabled: bool
    display_name: str


def _redirect_to_login(**params: str) -> RedirectResponse:
    from urllib.parse import urlencode

    response = RedirectResponse(f"/login?{urlencode(params)}", status_code=303)
    response.delete_cookie(_STATE_COOKIE, path=_STATE_COOKIE_PATH)
    return response


@router.get("/config", response_model=OIDCConfig)
async def oidc_config():
    """Public: lets the login page decide whether to offer an SSO button."""
    settings = get_settings()
    return OIDCConfig(enabled=settings.oidc_enabled, display_name=settings.oidc_display_name)


@router.get("/login")
@limiter.limit("20/minute")
async def oidc_login(request: Request):
    if not get_settings().oidc_enabled:
        return _redirect_to_login(sso_error="disabled")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = oidc.new_pkce_pair()
    try:
        url = await oidc.authorization_url(state, nonce, challenge)
        await auth_api._get_redis().set(
            f"{_STATE_PREFIX}{state}", json.dumps({"nonce": nonce, "verifier": verifier}), ex=_STATE_SECONDS
        )
    except oidc.OIDCError as exc:
        logger.error("SSO login could not start: %s", exc)
        return _redirect_to_login(sso_error=exc.code)
    except Exception:
        logger.exception("SSO login could not start")
        return _redirect_to_login(sso_error="unavailable")
    response = RedirectResponse(url, status_code=303)
    # Binds the flow to this browser, so a callback URL lured into another
    # browser cannot log that browser into the attacker's account. Lax, because
    # the callback arrives as a top-level navigation from the provider.
    response.set_cookie(
        _STATE_COOKIE,
        state,
        httponly=True,
        samesite="lax",
        secure=get_settings().secure_cookies,
        path=_STATE_COOKIE_PATH,
        max_age=_STATE_SECONDS,
    )
    return response


async def _resolve_user(db: AsyncSession, identity: oidc.Identity) -> User:
    settings = get_settings()
    domains = settings.oidc_domain_list
    if domains and identity.email.rsplit("@", 1)[-1] not in domains:
        raise oidc.OIDCError("domain_not_allowed", f"{identity.email} is outside OIDC_ALLOWED_DOMAINS")

    user = (await db.execute(select(User).where(User.oidc_subject == identity.subject))).scalar_one_or_none()
    if user is None:
        if identity.email_verified is False:
            raise oidc.OIDCError("email_unverified", f"provider reports {identity.email} as unverified")
        user = (await db.execute(select(User).where(User.email == identity.email))).scalar_one_or_none()
        if user is not None:
            if user.oidc_subject:
                # Already linked to a different identity; an email match must
                # not re-link it.
                raise oidc.OIDCError("account_conflict", f"{identity.email} is linked to another SSO identity")
            user.oidc_subject = identity.subject
            logger.info("Linked SSO identity to existing user=%s", user.email)
        elif settings.oidc_auto_create_users:
            user = User(
                id=new_uuid(),
                email=identity.email,
                # Unusable password: the account signs in through SSO until an
                # admin sets one.
                hashed_password=hash_password(secrets.token_urlsafe(48)),
                full_name=identity.name,
                role=settings.oidc_default_role,
                is_active=True,
                oidc_subject=identity.subject,
            )
            db.add(user)
            logger.info("Created user=%s role=%s from SSO", user.email, user.role)
        else:
            raise oidc.OIDCError("no_account", f"no ScanR account for {identity.email}")
    if not user.is_active:
        raise oidc.OIDCError("account_disabled", f"{user.email} is deactivated")
    return user


@router.get("/callback")
@limiter.limit("20/minute")
async def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    scanr_oidc_state: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
):
    if error:
        logger.warning("SSO provider returned error=%s", error[:100])
        return _redirect_to_login(sso_error="provider_denied")
    if not code or not state or not scanr_oidc_state or not secrets.compare_digest(state, scanr_oidc_state):
        return _redirect_to_login(sso_error="invalid_state")
    try:
        stored = await auth_api._get_redis().getdel(f"{_STATE_PREFIX}{state}")
    except Exception:
        logger.exception("Redis unavailable during SSO callback")
        return _redirect_to_login(sso_error="unavailable")
    if not stored:
        return _redirect_to_login(sso_error="invalid_state")
    flow = json.loads(stored)

    try:
        tokens = await oidc.exchange_code(code, flow["verifier"])
        identity = await oidc.validate_id_token(tokens["id_token"], flow["nonce"], tokens.get("access_token"))
        user = await _resolve_user(db, identity)
    except oidc.OIDCError as exc:
        await db.rollback()
        logger.warning("SSO login refused (%s): %s", exc.code, exc)
        await audit.record(request, "auth.sso_refused", status_code=303, details={"reason": exc.code, "detail": str(exc)[:200]})
        return _redirect_to_login(sso_error=exc.code)

    response = _redirect_to_login(sso="success")
    # The access token is discarded: the login page exchanges the refresh
    # cookie for one, keeping tokens out of URLs and browser history. ScanR's
    # own second factor is not asked for; the provider enforces its policy.
    await auth_api.start_session(db, response, user)
    logger.info("Successful SSO login: user=%s", user.email)
    await audit.record(request, "auth.login", user=user, status_code=303, details={"method": "sso"})
    return response
