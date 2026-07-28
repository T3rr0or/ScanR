"""finding retests

Retest history: re-running the plugin that produced a finding, against the same
target, and recording what it concluded. Kept as a table rather than a column on
findings because "still present on 12 Feb, verified fixed on 3 Mar" is the
evidence trail a retest report needs.

findings gains two denormalised columns for the latest outcome so the findings
list can show verification state without a per-row subquery.

Revision ID: 0021
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import (
        add_column_if_missing,
        create_index_if_missing,
        has_table,
    )

    if not has_table("finding_retests"):
        op.create_table(
            "finding_retests",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
            sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
            sa.Column("verdict", sa.String(20), nullable=True),
            sa.Column("evidence", sa.Text(), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
    create_index_if_missing(
        "ix_finding_retests_finding_id", "finding_retests", ["finding_id"]
    )

    add_column_if_missing(
        "findings", sa.Column("last_retest_at", sa.DateTime(timezone=True), nullable=True)
    )
    add_column_if_missing(
        "findings", sa.Column("last_retest_verdict", sa.String(20), nullable=True)
    )


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists, drop_index_if_exists, has_table

    drop_column_if_exists("findings", "last_retest_verdict")
    drop_column_if_exists("findings", "last_retest_at")
    drop_index_if_exists("ix_finding_retests_finding_id", "finding_retests")
    if has_table("finding_retests"):
        op.drop_table("finding_retests")
