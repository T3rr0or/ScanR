"""agent rate_limit_tokens_per_min

Add ai_agent_runs.rate_limit_tokens_per_min so a run can carry a per-minute
input-token rate cap. Null = fall back to the global AI_RATE_LIMIT_TOKENS_PER_MIN
setting, 0 = unlimited for this run.

Revision ID: 0018
"""
from typing import Sequence, Union

import sqlalchemy as sa


revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing(
        "ai_agent_runs", sa.Column("rate_limit_tokens_per_min", sa.Integer(), nullable=True)
    )


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("ai_agent_runs", "rate_limit_tokens_per_min")
