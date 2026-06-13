"""agent capabilities

Add ai_agent_runs.capabilities (JSON: aggressive opt-ins) so an agent run records
which aggressive capabilities were enabled at launch.

Revision ID: 0013
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("ai_agent_runs", sa.Column("capabilities", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_agent_runs", "capabilities")
