"""finding priority: EPSS, KEV flag and fix-first score

Revision ID: 0028
Revises: 0027
"""
from typing import Sequence, Union

import sqlalchemy as sa

revision: str = "0028"
down_revision: Union[str, None] = "0027"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing, create_index_if_missing

    add_column_if_missing("findings", sa.Column("priority_score", sa.Float(), nullable=True))
    add_column_if_missing("findings", sa.Column("priority_reasons", sa.Text(), nullable=True))
    add_column_if_missing("findings", sa.Column("epss_score", sa.Float(), nullable=True))
    add_column_if_missing("findings", sa.Column("epss_percentile", sa.Float(), nullable=True))
    add_column_if_missing(
        "findings", sa.Column("is_kev", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    # Existing findings are scored by the API's feed refresher on startup.
    create_index_if_missing("ix_findings_priority_score", "findings", ["priority_score"])


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists, drop_index_if_exists

    drop_index_if_exists("ix_findings_priority_score", "findings")
    for column in ("is_kev", "epss_percentile", "epss_score", "priority_reasons", "priority_score"):
        drop_column_if_exists("findings", column)
