"""testing activity log per scan

Revision ID: 0034
Revises: 0033
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0034"
down_revision: Union[str, None] = "0033"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import create_index_if_missing, has_table

    if not has_table("scan_activity"):
        op.create_table(
            "scan_activity",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("event", sa.String(length=40), nullable=False),
            sa.Column("detail", sa.Text(), nullable=True),
            sa.Column("source_ip", sa.String(length=255), nullable=True),
            sa.Column("actor", sa.String(length=255), nullable=True),
            sa.Column("prev_hash", sa.String(length=64), nullable=False),
            sa.Column("hash", sa.String(length=64), nullable=False),
        )
    create_index_if_missing("ix_scan_activity_scan_id", "scan_activity", ["scan_id"])


def downgrade() -> None:
    from scanr.db.migration_utils import has_table

    if has_table("scan_activity"):
        op.drop_table("scan_activity")
