"""host_tags table

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-29
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect, text

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_tables = {t for t in inspector.get_table_names()}
    if "host_tags" not in existing_tables:
        op.create_table(
            "host_tags",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("ip", sa.String(45), nullable=False),
            sa.Column("tag", sa.String(100), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("user_id", "ip", "tag", name="uq_host_tags"),
        )
        op.create_index("idx_host_tags_ip", "host_tags", ["ip"])
        op.create_index("idx_host_tags_user_tag", "host_tags", ["user_id", "tag"])


def downgrade() -> None:
    op.drop_table("host_tags")
