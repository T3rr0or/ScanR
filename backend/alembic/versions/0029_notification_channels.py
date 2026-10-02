"""notification channels: email, Teams and Slack scan summaries

Revision ID: 0029
Revises: 0028
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: Union[str, None] = "0028"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import create_index_if_missing, has_table

    if not has_table("notification_channels"):
        op.create_table(
            "notification_channels",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("kind", sa.String(length=20), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("events", sa.Text(), nullable=False),
            sa.Column("min_priority", sa.Float(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("last_status", sa.String(length=20), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
    create_index_if_missing("ix_notification_channels_user_id", "notification_channels", ["user_id"])


def downgrade() -> None:
    from scanr.db.migration_utils import has_table

    if has_table("notification_channels"):
        op.drop_table("notification_channels")
