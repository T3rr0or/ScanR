"""agent max_iterations

Add ai_agent_runs.max_iterations so a run can carry a user-chosen reasoning
iteration ceiling (set from the scan AI tab). Null = engine default.

Revision ID: 0015
"""
from typing import Sequence, Union

import sqlalchemy as sa


revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing("ai_agent_runs", sa.Column("max_iterations", sa.Integer(), nullable=True))


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("ai_agent_runs", "max_iterations")
