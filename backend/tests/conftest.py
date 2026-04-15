from __future__ import annotations

import asyncio
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from scanr.db.init_db import create_tables, seed_admin, seed_plugins
from scanr.db.session import get_db
from scanr.main import create_app

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
    from scanr import config as cfg_module
    import scanr.db.session as session_module

    # Override engine in session module
    session_module.engine = db_engine
    session_module.AsyncSessionLocal = async_sessionmaker(
        bind=db_engine, class_=AsyncSession, expire_on_commit=False
    )

    from scanr.models import Base
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
    resp = await client.post("/api/v1/auth/login", json={"email": "admin@scanr.local", "password": "changeme"})
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
