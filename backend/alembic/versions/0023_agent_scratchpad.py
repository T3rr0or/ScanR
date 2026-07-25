"""agent scratchpad

Working memory for an agent run: a todo list and topic-keyed notes.

Persisted rather than held in the loop so it survives the watchdog restarting a
stalled run, and so it appears in the exported trace — the agent's plan and its
recorded facts are the most useful part of an audit trail.

Revision ID: 0023
"""
from typing import Sequence, Union

import sqlalchemy as sa

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing("ai_agent_runs", sa.Column("scratchpad", sa.Text(), nullable=True))


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("ai_agent_runs", "scratchpad")
