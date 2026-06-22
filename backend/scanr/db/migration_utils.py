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
