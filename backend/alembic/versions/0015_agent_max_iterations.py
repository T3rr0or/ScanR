"""agent max_iterations

Add ai_agent_runs.max_iterations so a run can carry a user-chosen reasoning
iteration ceiling (set from the scan AI tab). Null = engine default.

Revision ID: 0015
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("ai_agent_runs", sa.Column("max_iterations", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_agent_runs", "max_iterations")
