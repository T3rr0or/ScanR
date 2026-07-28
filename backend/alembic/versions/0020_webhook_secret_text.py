"""widen webhooks.secret for encrypted storage

The webhook HMAC signing secret is now stored as Fernet ciphertext rather than
plaintext, and ciphertext is substantially longer than the plaintext it wraps —
String(255) would truncate or error on a long secret. Widen to Text.

Existing rows keep their plaintext value; the dispatcher reads both (it attempts
decryption and falls back to treating the value as legacy plaintext), so no data
migration is required and a rollback stays readable.

Revision ID: 0020
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import has_column

    if not has_column("webhooks", "secret"):
        return
    # SQLite cannot ALTER COLUMN types; it has no length enforcement on VARCHAR
    # either, so the existing column already behaves as Text there.
    if op.get_bind().dialect.name == "sqlite":
        return
    op.alter_column(
        "webhooks",
        "secret",
        existing_type=sa.String(255),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    from scanr.db.migration_utils import (
        has_column,
        refuse_narrowing_that_would_truncate,
    )

    if not has_column("webhooks", "secret"):
        return
    if op.get_bind().dialect.name == "sqlite":
        return
    # Fernet ciphertext passes 255 characters at around 110 characters of
    # plaintext, and the API accepts secrets up to 255 — so any real deployment
    # can hold rows this ALTER cannot store. It only ever "worked" against an
    # empty webhooks table.
    refuse_narrowing_that_would_truncate("webhooks", "secret", 255)
    op.alter_column(
        "webhooks",
        "secret",
        existing_type=sa.Text(),
        type_=sa.String(255),
        existing_nullable=True,
    )
