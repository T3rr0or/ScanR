"""agent conversation

Add conversation JSON column so chat-style follow-up messages are persisted
and can be resumed across Celery task invocations.

Revision ID: 0016
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ai_agent_runs",
        sa.Column("conversation", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("ai_agent_runs", "conversation")
