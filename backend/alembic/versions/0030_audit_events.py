"""append-only audit log

Revision ID: 0030
Revises: 0029
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: Union[str, None] = "0029"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import create_index_if_missing, has_table

    if not has_table("audit_events"):
        op.create_table(
            "audit_events",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("user_email", sa.String(length=255), nullable=True),
            sa.Column("auth_method", sa.String(length=20), nullable=True),
            sa.Column("ip", sa.String(length=64), nullable=True),
            sa.Column("action", sa.String(length=100), nullable=False),
            sa.Column("target_type", sa.String(length=50), nullable=True),
            sa.Column("target_id", sa.String(length=100), nullable=True),
            sa.Column("method", sa.String(length=10), nullable=True),
            sa.Column("path", sa.String(length=300), nullable=True),
            sa.Column("status_code", sa.Integer(), nullable=True),
            sa.Column("details", sa.Text(), nullable=True),
        )
    for column in ("created_at", "user_id", "action", "target_id"):
        create_index_if_missing(f"ix_audit_events_{column}", "audit_events", [column])


def downgrade() -> None:
    from scanr.db.migration_utils import has_table

    if has_table("audit_events"):
        op.drop_table("audit_events")
