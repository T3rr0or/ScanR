"""agent pending_approval

Add ai_agent_runs.pending_approval so a guided run can pause and surface the
intrusive action awaiting an operator allow/deny decision.

Revision ID: 0012
"""
from typing import Sequence, Union

import sqlalchemy as sa


revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing("ai_agent_runs", sa.Column("pending_approval", sa.Text(), nullable=True))


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("ai_agent_runs", "pending_approval")
