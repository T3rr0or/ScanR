"""durable password generation

Stores refresh-token generation beside the password hash so both rotate in one
database transaction.

Revision ID: 0025
"""
from typing import Sequence, Union

import sqlalchemy as sa

revision: str = "0025"
down_revision: Union[str, None] = "0024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing

    add_column_if_missing(
        "users", sa.Column("password_generation", sa.String(length=36), nullable=True)
    )


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists

    drop_column_if_exists("users", "password_generation")
