"""scan_heartbeat

Add scans.last_heartbeat so a background watchdog can detect scans whose
worker died mid-run (OOM/SIGKILL) and mark them failed instead of leaving them
stuck in "running" forever.

Revision ID: 0008
"""
from typing import Sequence, Union

import sqlalchemy as sa


revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing("scans", sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("scans", "last_heartbeat")
