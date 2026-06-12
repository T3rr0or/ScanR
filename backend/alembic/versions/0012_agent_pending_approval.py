"""agent pending_approval

Add ai_agent_runs.pending_approval so a guided run can pause and surface the
intrusive action awaiting an operator allow/deny decision.

Revision ID: 0012
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("ai_agent_runs", sa.Column("pending_approval", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_agent_runs", "pending_approval")
