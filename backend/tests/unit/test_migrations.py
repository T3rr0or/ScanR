"""Migration build tests.

The rest of the suite builds the schema with ``Base.metadata.create_all`` and so
never exercises the Alembic chain — yet production/self-update applies migrations
on startup (``scanr.db.init_db.run_migrations``). These tests run the real chain
on a throwaway SQLite DB and assert it (a) has a single head, (b) upgrades from
empty to head cleanly, and (c) produces every table/column the ORM models declare
— catching the classic "added a model field but forgot the migration" break.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

_ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


def _config(db_url: str) -> Config:
    cfg = Config(str(_ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_single_head() -> None:
    """A divergent chain (two heads) silently breaks `upgrade head` on update."""
    script = ScriptDirectory.from_config(_config("sqlite://"))
    heads = script.get_heads()
    assert len(heads) == 1, f"expected exactly one migration head, found {heads}"


def test_upgrade_head_builds_model_schema() -> None:
    import scanr.models  # noqa: F401 — register all ORM classes on Base
    from scanr.models.base import Base

    with tempfile.TemporaryDirectory() as tmp:
        db_file = Path(tmp) / "mig.db"
        # Alembic env runs async online, so it needs the aiosqlite driver.
        command.upgrade(_config(f"sqlite+aiosqlite:///{db_file}"), "head")

        engine = create_engine(f"sqlite:///{db_file}")
        try:
            insp = inspect(engine)
            tables = set(insp.get_table_names())
            for table in Base.metadata.sorted_tables:
                assert table.name in tables, f"migrations missing table {table.name!r}"
                cols = {c["name"] for c in insp.get_columns(table.name)}
                missing = {c.name for c in table.columns} - cols
                assert not missing, f"{table.name} missing migrated column(s): {missing}"
        finally:
            engine.dispose()
