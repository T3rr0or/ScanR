"""ticket links

Links a finding to its ticket in an external system (TOPdesk today; the provider
column keeps Jira/ServiceNow a new value rather than a new migration).

The unique constraint on (finding_id, provider) is load-bearing: it is what stops
two concurrent "create ticket" requests from opening two tickets for one finding.

Revision ID: 0022
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import create_index_if_missing, has_table

    if not has_table("ticket_links"):
        op.create_table(
            "ticket_links",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
            sa.Column("provider", sa.String(32), nullable=False),
            sa.Column("external_id", sa.String(128), nullable=False),
            sa.Column("external_key", sa.String(128), nullable=True),
            sa.Column("url", sa.Text(), nullable=True),
            sa.Column("external_status", sa.String(64), nullable=True),
            sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.UniqueConstraint("finding_id", "provider", name="uq_ticket_links_finding_provider"),
        )
    create_index_if_missing("ix_ticket_links_finding_id", "ticket_links", ["finding_id"])


def downgrade() -> None:
    from scanr.db.migration_utils import drop_index_if_exists, has_table

    drop_index_if_exists("ix_ticket_links_finding_id", "ticket_links")
    if has_table("ticket_links"):
        op.drop_table("ticket_links")
