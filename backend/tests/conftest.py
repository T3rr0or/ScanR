from __future__ import annotations

import asyncio
import os
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Must be set before pydantic-settings reads env on first import
os.environ.setdefault("SECRET_KEY", "test-secret-key-minimum-32-characters-long!!")
os.environ.setdefault("ADMIN_PASSWORD", "testadminpass123")
os.environ.setdefault("ADMIN_EMAIL", "admin@scanr.local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_scanr.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SECURE_COOKIES", "false")
if not os.environ.get("VAULT_KEY"):
    from cryptography.fernet import Fernet

    os.environ["VAULT_KEY"] = Fernet.generate_key().decode()

from scanr.core.limiter import limiter  # noqa: E402
from scanr.db.init_db import seed_admin, seed_plugins  # noqa: E402
from scanr.main import create_app  # noqa: E402

# Keep tests deterministic: endpoint-specific rate limits are covered by SlowAPI,
# not by this app suite. Without this, repeated auth fixture logins can trip
# /auth/login's 10/minute limit and make unrelated tests fail.
limiter.enabled = False

# Patch Redis with fakeredis so auth (jti revocation) tests work without a real Redis
import fakeredis.aioredis as _fake_aioredis  # noqa: E402
import scanr.api.v1.auth as _auth_module  # noqa: E402

_FAKE_REDIS_SERVER = _fake_aioredis.FakeServer()


def _fake_get_redis():
    return _fake_aioredis.FakeRedis(server=_FAKE_REDIS_SERVER, decode_responses=True)


_auth_module._get_redis = _fake_get_redis  # type: ignore[attr-defined]

TEST_DB_URL = "sqlite+aiosqlite:///./test_scanr.db"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})

    # SQLite doesn't enforce foreign keys unless asked per-connection. Turn it on
    # so tests actually exercise FK constraints (e.g. the user-delete cascade
    # order) the way Postgres would in production.
    from sqlalchemy import event

    @event.listens_for(engine.sync_engine, "connect")
    def _fk_pragma(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    yield engine
    await engine.dispose()


@pytest.fixture(scope="session")
async def test_app(db_engine):
    import scanr.db.session as session_module

    session_module.engine = db_engine
    session_module.AsyncSessionLocal = async_sessionmaker(bind=db_engine, class_=AsyncSession, expire_on_commit=False)

    import scanr.models  # noqa: F401 — registers all ORM classes with Base
    from scanr.models.base import Base

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with session_module.AsyncSessionLocal() as db:
        await seed_admin(db)
        await seed_plugins(db)

    app = create_app()
    yield app


@pytest.fixture
async def client(test_app):
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def db(test_app):
    """A DB session for tests that need to set up rows directly (e.g. agent runs
    that can't be created via the API without a live provider key)."""
    import scanr.db.session as session_module

    async with session_module.AsyncSessionLocal() as session:
        yield session


@pytest.fixture
async def auth_headers(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "testadminpass123"},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
