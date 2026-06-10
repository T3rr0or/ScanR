"""scan_heartbeat

Add scans.last_heartbeat so a background watchdog can detect scans whose
worker died mid-run (OOM/SIGKILL) and mark them failed instead of leaving them
stuck in "running" forever.

Revision ID: 0008
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "last_heartbeat")
