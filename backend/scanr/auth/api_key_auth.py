from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.models.api_key import APIKey
from scanr.models.user import User


def generate_api_key() -> tuple[str, str, str]:
    """Returns (raw_key, key_hash, prefix)."""
    raw = "sk_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    prefix = raw[:12]
    return raw, key_hash, prefix


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def get_user_from_api_key(raw_key: str, db: AsyncSession) -> tuple[User | None, list[str]]:
    """Validate an API key and return (user, scopes), or (None, [])."""
    key_hash = hash_api_key(raw_key)
    result = await db.execute(
        select(APIKey).where(
            APIKey.key_hash == key_hash,
            APIKey.revoked == False,
        )
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        return None, []

    now = datetime.now(timezone.utc)
    if api_key.expires_at and api_key.expires_at < now:
        return None, []

    scopes: list[str] = json.loads(api_key.scopes) if api_key.scopes else []

    # Update last_used_at without committing — the request's normal session lifecycle handles that
    api_key.last_used_at = now
    await db.flush()

    user_result = await db.execute(select(User).where(User.id == api_key.user_id, User.is_active == True))
    user = user_result.scalar_one_or_none()
    return user, scopes
