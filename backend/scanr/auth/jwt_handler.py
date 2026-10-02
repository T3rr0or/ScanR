from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

from scanr.config import get_settings

settings = get_settings()


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def create_access_token(subject: str, role: str) -> str:
    expire = _now() + timedelta(minutes=settings.access_token_expire_minutes)
    return jwt.encode(
        {"sub": subject, "role": role, "exp": expire, "type": "access"},
        settings.secret_key,
        algorithm=settings.algorithm,
    )


def create_refresh_token(subject: str, password_generation: str | None = None) -> str:
    issued = _now()
    expire = issued + timedelta(days=settings.refresh_token_expire_days)
    return jwt.encode(
        {
            "sub": subject,
            "exp": expire,
            "type": "refresh",
            "jti": str(uuid.uuid4()),
            # An exact generation marker avoids timestamp-boundary races. It is
            # omitted until a user has changed their password, preserving compact
            # tokens for accounts with no revocation marker in Redis.
            **({"pw_generation": password_generation} if password_generation else {}),
        },
        settings.secret_key,
        algorithm=settings.algorithm,
    )


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError as exc:
        raise ValueError("Invalid token") from exc


MFA_TOKEN_MINUTES = 5


def create_mfa_token(subject: str, password_generation: str | None = None) -> str:
    """Proof that the password step passed, valid only for /auth/login/mfa."""
    return jwt.encode(
        {
            "sub": subject,
            "exp": _now() + timedelta(minutes=MFA_TOKEN_MINUTES),
            "type": "mfa",
            "jti": str(uuid.uuid4()),
            **({"pw_generation": password_generation} if password_generation else {}),
        },
        settings.secret_key,
        algorithm=settings.algorithm,
    )
