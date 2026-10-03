"""finding library: reusable write-ups, finding impact and template link

Revision ID: 0031
Revises: 0030
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: Union[str, None] = "0030"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing, create_index_if_missing, has_table

    if not has_table("finding_templates"):
        op.create_table(
            "finding_templates",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("title", sa.String(length=512), nullable=False, unique=True),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("cvss_score", sa.Float(), nullable=True),
            sa.Column("cvss_vector", sa.String(length=255), nullable=True),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("impact", sa.Text(), nullable=True),
            sa.Column("remediation", sa.Text(), nullable=True),
            sa.Column("references", sa.Text(), nullable=True),
            sa.Column("cve_ids", sa.Text(), nullable=True),
            sa.Column("tags", sa.Text(), nullable=True),
            sa.Column("plugin_ids", sa.Text(), nullable=True),
            sa.Column("title_match", sa.String(length=255), nullable=True),
            sa.Column("created_by", sa.String(length=255), nullable=True),
            sa.Column("updated_by", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
    add_column_if_missing("findings", sa.Column("impact", sa.Text(), nullable=True))
    add_column_if_missing("findings", sa.Column("template_id", sa.String(length=36), nullable=True))
    create_index_if_missing("ix_findings_template_id", "findings", ["template_id"])


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists, drop_index_if_exists, has_table

    drop_index_if_exists("ix_findings_template_id", "findings")
    drop_column_if_exists("findings", "template_id")
    drop_column_if_exists("findings", "impact")
    if has_table("finding_templates"):
        op.drop_table("finding_templates")
