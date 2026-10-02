"""two-factor authentication and single sign-on identity

Revision ID: 0027
Revises: 0026
"""
from typing import Sequence, Union

import sqlalchemy as sa

revision: str = "0027"
down_revision: Union[str, None] = "0026"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing, create_index_if_missing

    add_column_if_missing("users", sa.Column("totp_secret", sa.Text(), nullable=True))
    add_column_if_missing(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    add_column_if_missing("users", sa.Column("totp_last_step", sa.BigInteger(), nullable=True))
    add_column_if_missing("users", sa.Column("totp_recovery_codes", sa.Text(), nullable=True))
    add_column_if_missing("users", sa.Column("oidc_subject", sa.String(length=255), nullable=True))
    create_index_if_missing("ix_users_oidc_subject", "users", ["oidc_subject"], unique=True)


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists, drop_index_if_exists

    drop_index_if_exists("ix_users_oidc_subject", "users")
    for column in ("oidc_subject", "totp_recovery_codes", "totp_last_step", "totp_enabled", "totp_secret"):
        drop_column_if_exists("users", column)
