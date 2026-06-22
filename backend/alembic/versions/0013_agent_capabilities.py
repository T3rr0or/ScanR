"""agent capabilities

Add ai_agent_runs.capabilities (JSON: aggressive opt-ins) so an agent run records
which aggressive capabilities were enabled at launch.

Revision ID: 0013
"""
from typing import Sequence, Union

import sqlalchemy as sa


revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing("ai_agent_runs", sa.Column("capabilities", sa.Text(), nullable=True))


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("ai_agent_runs", "capabilities")
