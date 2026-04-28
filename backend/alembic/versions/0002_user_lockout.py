"""user lockout columns

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-26

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_cols = {c["name"] for c in inspector.get_columns("users")}

    if "failed_login_count" not in existing_cols:
        op.add_column("users", sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"))
    if "locked_until" not in existing_cols:
        op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_count")
