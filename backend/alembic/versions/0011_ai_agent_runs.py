"""ai_agent_runs

Stores guided/autonomous AI agent runs against a scan (status, transcript of
actions, final assessment, token usage) so they survive reloads.

Revision ID: 0011
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import has_table

    if has_table("ai_agent_runs"):
        return
    op.create_table(
        "ai_agent_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued", index=True),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(32), nullable=True),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("stop_reason", sa.String(32), nullable=True),
        sa.Column("final_text", sa.Text(), nullable=True),
        sa.Column("actions", sa.Text(), nullable=True),
        sa.Column("token_usage", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ai_agent_runs")
