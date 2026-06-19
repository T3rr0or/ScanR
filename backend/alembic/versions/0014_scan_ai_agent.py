"""scan ai agent auto-run

Add ai_agent_* columns to scans so a scan can opt into launching an AI agent
run concurrently when it starts (configured at scan-creation time).

Revision ID: 0014
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("ai_agent_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("scans", sa.Column("ai_agent_mode", sa.String(length=20), nullable=True))
    op.add_column("scans", sa.Column("ai_agent_objective", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("ai_agent_provider", sa.String(length=40), nullable=True))
    op.add_column("scans", sa.Column("ai_agent_model", sa.String(length=120), nullable=True))
    op.add_column("scans", sa.Column("ai_agent_capabilities", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "ai_agent_capabilities")
    op.drop_column("scans", "ai_agent_model")
    op.drop_column("scans", "ai_agent_provider")
    op.drop_column("scans", "ai_agent_objective")
    op.drop_column("scans", "ai_agent_mode")
    op.drop_column("scans", "ai_agent_enabled")
