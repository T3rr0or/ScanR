"""Encrypt and version every stored webhook signing secret.

Revision ID: 0026
Revises: 0025

The previous runtime accepted raw Fernet tokens and plaintext in the same
column. That made corrupt ciphertext and a missing/wrong VAULT_KEY silently turn
into a usable plaintext signing key. This migration removes the ambiguity while
preserving both legacy forms and a safe downgrade path.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: Union[str, None] = "0025"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PREFIX = "enc:v1:"


def upgrade() -> None:
    from scanr.credentials import vault
    from scanr.db.migration_utils import has_column
    from scanr.utils.exceptions import VaultError

    if not has_column("webhooks", "secret"):
        return

    webhooks = sa.table(
        "webhooks",
        sa.column("id", sa.String(length=36)),
        sa.column("secret", sa.Text()),
    )
    bind = op.get_bind()
    rows = bind.execute(
        sa.select(webhooks.c.id, webhooks.c.secret).where(
            webhooks.c.secret.is_not(None), webhooks.c.secret != ""
        )
    ).all()

    for webhook_id, stored in rows:
        if not isinstance(stored, str):
            raise RuntimeError(f"Webhook {webhook_id} has a non-text signing secret")
        try:
            if stored.startswith(_PREFIX):
                # Validate already-versioned rows so a wrong key or corrupt value
                # stops startup rather than producing unsigned deliveries later.
                payload = vault.decrypt(stored.removeprefix(_PREFIX))
                migrated = stored
            elif stored.startswith("gAAAA"):
                # Raw Fernet is the format written by releases before 0026.
                payload = vault.decrypt(stored)
                migrated = _PREFIX + stored
            else:
                # Older releases could fall back to plaintext. Encrypt those rows
                # in-place; failure (including no key) aborts the transaction.
                payload = {"v": stored}
                migrated = _PREFIX + vault.encrypt(payload)
            if not isinstance(payload.get("v"), str) or not payload["v"]:
                raise VaultError("decrypted payload does not contain a non-empty string 'v'")
        except (VaultError, TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Cannot migrate signing secret for webhook {webhook_id}: {exc}"
            ) from exc

        if migrated != stored:
            bind.execute(
                sa.update(webhooks)
                .where(webhooks.c.id == webhook_id)
                .values(secret=migrated)
            )


def downgrade() -> None:
    from scanr.db.migration_utils import has_column

    if not has_column("webhooks", "secret"):
        return

    webhooks = sa.table(
        "webhooks",
        sa.column("id", sa.String(length=36)),
        sa.column("secret", sa.Text()),
    )
    bind = op.get_bind()
    rows = bind.execute(
        sa.select(webhooks.c.id, webhooks.c.secret).where(
            webhooks.c.secret.like(f"{_PREFIX}%")
        )
    ).all()
    for webhook_id, stored in rows:
        bind.execute(
            sa.update(webhooks)
            .where(webhooks.c.id == webhook_id)
            .values(secret=stored.removeprefix(_PREFIX))
        )
