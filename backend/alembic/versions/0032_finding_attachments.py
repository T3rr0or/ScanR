"""evidence attachments on findings

Revision ID: 0032
Revises: 0031
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0032"
down_revision: Union[str, None] = "0031"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import create_index_if_missing, has_table

    if not has_table("finding_attachments"):
        op.create_table(
            "finding_attachments",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("finding_id", sa.String(length=36),
                      sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
            sa.Column("filename", sa.String(length=255), nullable=False),
            sa.Column("content_type", sa.String(length=100), nullable=False),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("caption", sa.Text(), nullable=True),
            sa.Column("uploaded_by", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
    create_index_if_missing("ix_finding_attachments_finding_id", "finding_attachments", ["finding_id"])


def downgrade() -> None:
    from scanr.db.migration_utils import has_table

    if has_table("finding_attachments"):
        op.drop_table("finding_attachments")
