"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-04-24

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
from sqlalchemy import inspect as sa_inspect, text

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "users" not in existing_tables:
        # Fresh install — create the full schema via SQLAlchemy metadata
        from scanr.models.base import Base
        import scanr.models  # noqa: F401 — registers all ORM classes
        Base.metadata.create_all(bind)
    else:
        # Existing install — patch columns that were added before Alembic was introduced
        if "scans" in existing_tables:
            existing_cols = {c["name"] for c in inspector.get_columns("scans")}
            if "compare_scan_id" not in existing_cols:
                op.execute(text(
                    "ALTER TABLE scans ADD COLUMN compare_scan_id "
                    "VARCHAR(36) REFERENCES scans(id)"
                ))
            if "webhook_sent" not in existing_cols:
                op.execute(text(
                    "ALTER TABLE scans ADD COLUMN webhook_sent "
                    "BOOLEAN NOT NULL DEFAULT FALSE"
                ))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    if "scans" in set(inspector.get_table_names()):
        cols = {c["name"] for c in inspector.get_columns("scans")}
        if "compare_scan_id" in cols:
            op.drop_constraint("scans_compare_scan_id_fkey", "scans", type_="foreignkey")
            op.drop_column("scans", "compare_scan_id")
        if "webhook_sent" in cols:
            op.drop_column("scans", "webhook_sent")
