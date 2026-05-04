"""create schedules table

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-01
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_tables = {t for t in inspector.get_table_names()}
    if "schedules" in existing_tables:
        return

    op.create_table(
        "schedules",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("targets", sa.Text(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("scan_profile_json", sa.Text(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("cron_expr", sa.String(length=100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("next_run", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_schedules_user_id", "schedules", ["user_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    if "schedules" not in set(inspector.get_table_names()):
        return
    op.drop_index("ix_schedules_user_id", table_name="schedules")
    op.drop_table("schedules")
