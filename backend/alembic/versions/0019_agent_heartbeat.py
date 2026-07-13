"""agent run heartbeat

Add ai_agent_runs.last_heartbeat so a watchdog can fail agent runs whose worker
died mid-run (otherwise they hang "running" forever and block chat/resume).

Revision ID: 0019
"""
from typing import Sequence, Union

import sqlalchemy as sa


revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing(
        "ai_agent_runs", sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("ai_agent_runs", "last_heartbeat")
