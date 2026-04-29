"""vpr_score column on findings

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-29
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_cols = {c["name"] for c in inspector.get_columns("findings")}
    if "vpr_score" not in existing_cols:
        op.add_column("findings", sa.Column("vpr_score", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "vpr_score")
