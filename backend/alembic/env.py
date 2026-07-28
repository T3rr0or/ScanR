from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

config = context.config

if config.config_file_name is not None:
    # disable_existing_loggers=False is essential, not cosmetic. run_migrations()
    # is called from the app's lifespan startup, by which point every module has
    # already created its logger via getLogger(__name__). fileConfig's default
    # (True) sets .disabled on all of them, so the API and worker would run with
    # application logging silently switched off for the rest of the process —
    # losing failed-login warnings, blocked-webhook warnings, scope-violation
    # warnings and the rest.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Pull DATABASE_URL from environment so both CLI and programmatic use work
_db_url = config.get_main_option("sqlalchemy.url") or os.environ.get("DATABASE_URL", "")
config.set_main_option("sqlalchemy.url", _db_url)

# Import all models so their tables are registered on Base.metadata
from scanr.models import Base  # noqa: E402, F401
import scanr.models  # noqa: E402, F401

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
