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

from scanr.db.init_db import seed_admin, seed_plugins  # noqa: E402
from scanr.main import create_app  # noqa: E402

TEST_DB_URL = "sqlite+aiosqlite:///./test_scanr.db"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    yield engine
    await engine.dispose()


@pytest.fixture(scope="session")
async def test_app(db_engine):
    import scanr.db.session as session_module

    session_module.engine = db_engine
    session_module.AsyncSessionLocal = async_sessionmaker(
        bind=db_engine, class_=AsyncSession, expire_on_commit=False
    )

    import scanr.models  # noqa: F401 — registers all ORM classes with Base
    from scanr.models.base import Base
    async with db_engine.begin() as conn:
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
async def auth_headers(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "testadminpass123"},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
