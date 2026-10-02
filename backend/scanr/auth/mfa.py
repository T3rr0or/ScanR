"""Check a user's second factor: an authenticator code or a recovery code."""
from __future__ import annotations

import json

from sqlalchemy import or_, update
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.auth import totp
from scanr.credentials import vault
from scanr.models.user import User


def encrypt_secret(secret: str) -> str:
    return vault.encrypt({"totp_secret": secret})


def decrypt_secret(ciphertext: str) -> str:
    return str(vault.decrypt(ciphertext)["totp_secret"])


def recovery_hashes(user: User) -> list[str]:
    if not user.totp_recovery_codes:
        return []
    return list(json.loads(user.totp_recovery_codes))


async def verify_second_factor(db: AsyncSession, user: User, code: str) -> bool:
    """Accept a fresh authenticator code or an unused recovery code.

    Both are claimed with a conditional UPDATE, so two concurrent requests
    carrying the same code cannot both succeed. The caller commits.
    """
    if not user.totp_secret:
        return False
    step = totp.verify(decrypt_secret(user.totp_secret), code, user.totp_last_step)
    if step is not None:
        result = await db.execute(
            update(User)
            .where(
                User.id == user.id,
                or_(User.totp_last_step.is_(None), User.totp_last_step < step),
            )
            .values(totp_last_step=step)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 1:  # type: ignore[attr-defined]
            user.totp_last_step = step
            return True
        return False

    stored = user.totp_recovery_codes
    remaining = totp.consume_recovery_code(code, recovery_hashes(user))
    if remaining is None:
        return False
    result = await db.execute(
        update(User)
        .where(User.id == user.id, User.totp_recovery_codes == stored)
        .values(totp_recovery_codes=json.dumps(remaining))
        .execution_options(synchronize_session=False)
    )
    if result.rowcount == 1:  # type: ignore[attr-defined]
        user.totp_recovery_codes = json.dumps(remaining)
        return True
    return False
