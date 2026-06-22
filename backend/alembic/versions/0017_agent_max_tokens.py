"""agent max_tokens

Add ai_agent_runs.max_tokens so a run can carry a user-chosen token safety cap
(set from the scan AI tab, next to Max steps). Null = engine default (~200k).

Revision ID: 0017
"""
from typing import Sequence, Union

import sqlalchemy as sa


revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing("ai_agent_runs", sa.Column("max_tokens", sa.Integer(), nullable=True))


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("ai_agent_runs", "max_tokens")
