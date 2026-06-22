"""agent conversation

Add conversation JSON column so chat-style follow-up messages are persisted
and can be resumed across Celery task invocations.

Revision ID: 0016
"""

from typing import Sequence, Union

import sqlalchemy as sa

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing("ai_agent_runs", sa.Column("conversation", sa.Text(), nullable=True))


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("ai_agent_runs", "conversation")
