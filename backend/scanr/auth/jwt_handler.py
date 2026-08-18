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


def create_refresh_token(subject: str) -> str:
    issued = _now()
    expire = issued + timedelta(days=settings.refresh_token_expire_days)
    return jwt.encode(
        {
            "sub": subject,
            "exp": expire,
            "type": "refresh",
            "jti": str(uuid.uuid4()),
            # Milliseconds, not the standard second-granularity `iat`: a password
            # change bumps the revocation epoch and immediately mints a
            # replacement token, so both land in the same second and whole
            # seconds cannot tell the revoked token from its replacement.
            "iat_ms": int(issued.timestamp() * 1000),
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
