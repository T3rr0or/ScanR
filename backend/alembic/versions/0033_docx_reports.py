"""word reports: report options, template link, uploaded templates

Revision ID: 0033
Revises: 0032
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0033"
down_revision: Union[str, None] = "0032"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing, has_table

    add_column_if_missing("reports", sa.Column("options", sa.Text(), nullable=True))
    add_column_if_missing("reports", sa.Column("template_id", sa.String(length=36), nullable=True))
    if not has_table("report_templates"):
        op.create_table(
            "report_templates",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("name", sa.String(length=255), nullable=False, unique=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("filename", sa.String(length=255), nullable=False),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column("uploaded_by", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists, has_table

    if has_table("report_templates"):
        op.drop_table("report_templates")
    drop_column_if_exists("reports", "template_id")
    drop_column_if_exists("reports", "options")
