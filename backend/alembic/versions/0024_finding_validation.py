"""finding validation

Records that a finding was mechanically reproduced — a payload that actually
executed in a real browser — rather than pattern-matched. Indexed because the
point of the flag is filtering a long findings list down to the ones nobody has
to argue about.

Revision ID: 0024
"""
from typing import Sequence, Union

import sqlalchemy as sa

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from scanr.db.migration_utils import add_column_if_missing, create_index_if_missing

    add_column_if_missing(
        "findings",
        sa.Column("validated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    add_column_if_missing("findings", sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True))
    add_column_if_missing("findings", sa.Column("validation_method", sa.String(length=40), nullable=True))
    add_column_if_missing("findings", sa.Column("validation_evidence", sa.Text(), nullable=True))
    create_index_if_missing("ix_findings_validated", "findings", ["validated"])


def downgrade() -> None:
    from scanr.db.migration_utils import drop_column_if_exists, drop_index_if_exists

    drop_index_if_exists("ix_findings_validated", "findings")
    for column in ("validation_evidence", "validation_method", "validated_at", "validated"):
        drop_column_if_exists("findings", column)
