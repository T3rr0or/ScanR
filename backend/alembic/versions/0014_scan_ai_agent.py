"""scan ai agent auto-run

Add ai_agent_* columns to scans so a scan can opt into launching an AI agent
run concurrently when it starts (configured at scan-creation time).

Revision ID: 0014
"""
from typing import Sequence, Union

import sqlalchemy as sa


revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing(
        "scans", sa.Column("ai_agent_enabled", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    add_column_if_missing("scans", sa.Column("ai_agent_mode", sa.String(length=20), nullable=True))
    add_column_if_missing("scans", sa.Column("ai_agent_objective", sa.Text(), nullable=True))
    add_column_if_missing("scans", sa.Column("ai_agent_provider", sa.String(length=40), nullable=True))
    add_column_if_missing("scans", sa.Column("ai_agent_model", sa.String(length=120), nullable=True))
    add_column_if_missing("scans", sa.Column("ai_agent_capabilities", sa.Text(), nullable=True))


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    for col in (
        "ai_agent_capabilities",
        "ai_agent_model",
        "ai_agent_provider",
        "ai_agent_objective",
        "ai_agent_mode",
        "ai_agent_enabled",
    ):
        drop_column_if_exists("scans", col)
