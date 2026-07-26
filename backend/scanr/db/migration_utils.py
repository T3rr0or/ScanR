"""Idempotency helpers for Alembic migrations.

Migration 0001 builds a *fresh* install from the current ``Base.metadata`` via
``create_all`` (see 0001_initial_schema). That means on a brand-new database the
schema already matches the latest models, so any later ``add_column`` /
``create_table`` / ``create_index`` for an object the models now declare would
collide ("duplicate column", "table already exists"). Routing those operations
through these guards makes every post-0001 migration safe to run on both a fresh
DB (object already present → skip) and an older incremental DB (object missing →
apply). Keep using them for new schema migrations.
"""
from __future__ import annotations

from alembic import op
from sqlalchemy import inspect


def _inspector():
    return inspect(op.get_bind())


def has_table(table: str) -> bool:
    return table in set(_inspector().get_table_names())


def has_column(table: str, column: str) -> bool:
    if not has_table(table):
        return False
    return column in {c["name"] for c in _inspector().get_columns(table)}


def has_index(table: str, index: str) -> bool:
    if not has_table(table):
        return False
    return index in {ix["name"] for ix in _inspector().get_indexes(table)}


def add_column_if_missing(table: str, column) -> None:
    if not has_column(table, column.name):
        op.add_column(table, column)


def create_index_if_missing(name: str, table: str, columns, **kw) -> None:
    if not has_index(table, name):
        op.create_index(name, table, columns, **kw)


def drop_column_if_exists(table: str, column: str) -> None:
    if has_column(table, column):
        op.drop_column(table, column)


def drop_index_if_exists(name: str, table: str) -> None:
    if has_index(table, name):
        op.drop_index(name, table_name=table)


def refuse_narrowing_that_would_truncate(table: str, column: str, max_length: int) -> None:
    """Abort before an ALTER that would silently destroy data.

    A downgrade that narrows a widened column succeeds on an empty table and
    fails — or worse, truncates — on a populated one. That is exactly how the
    0020 rollback behaved: it passed in testing because ``webhooks`` was empty,
    and hit ``StringDataRightTruncationError`` the moment a real Fernet
    ciphertext (past 255 characters at roughly 110 characters of plaintext) was
    present. Truncating an HMAC signing secret would leave every webhook
    silently failing signature verification with nothing in the logs.

    So: check first, and if any row would not fit, stop with an error that says
    what to do about it. Rolling back is the operator's call to make knowingly.
    """
    from sqlalchemy import String, func, select
    from sqlalchemy import column as sa_column
    from sqlalchemy import table as sa_table

    if not has_column(table, column):
        return
    bind = op.get_bind()
    col = sa_column(column, String)
    stmt = (
        select(func.count())
        .select_from(sa_table(table, col))
        .where(func.length(col) > max_length)
    )
    offenders = bind.execute(stmt).scalar() or 0
    if offenders:
        raise RuntimeError(
            f"Refusing to narrow {table}.{column} to {max_length} characters: "
            f"{offenders} row(s) are longer and would be truncated or rejected. "
            f"Truncating this value corrupts it silently. Resolve it deliberately "
            f"first — shorten or clear the offending rows "
            f"(UPDATE {table} SET {column} = NULL WHERE length({column}) > {max_length}), "
            f"re-issue the affected secrets afterwards, then re-run the downgrade."
        )
