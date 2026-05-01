"""plugin run telemetry

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-01
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_tables = {t for t in inspector.get_table_names()}
    if "plugin_runs" in existing_tables:
        return

    op.create_table(
        "plugin_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("host_id", sa.String(36), sa.ForeignKey("hosts.id"), nullable=True),
        sa.Column("plugin_id", sa.String(100), sa.ForeignKey("plugins.id"), nullable=False),
        sa.Column("host_ip", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_plugin_runs_scan_id", "plugin_runs", ["scan_id"])
    op.create_index("ix_plugin_runs_host_id", "plugin_runs", ["host_id"])
    op.create_index("ix_plugin_runs_plugin_id", "plugin_runs", ["plugin_id"])
    op.create_index("ix_plugin_runs_status", "plugin_runs", ["status"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    if "plugin_runs" not in set(inspector.get_table_names()):
        return
    op.drop_index("ix_plugin_runs_status", table_name="plugin_runs")
    op.drop_index("ix_plugin_runs_plugin_id", table_name="plugin_runs")
    op.drop_index("ix_plugin_runs_host_id", table_name="plugin_runs")
    op.drop_index("ix_plugin_runs_scan_id", table_name="plugin_runs")
    op.drop_table("plugin_runs")
