"""Watchdog behaviour for unbounded agent runs."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from scanr.models import AiAgentRun
from scanr.models.base import Base
from scanr.tasks import agent_tasks


@pytest.fixture
async def reaper_db(tmp_path, monkeypatch):
    url = f"sqlite+aiosqlite:///{tmp_path / 'reaper.db'}"
    engine = create_async_engine(url, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()

    def _make():
        e = create_async_engine(url, poolclass=NullPool)
        return e, async_sessionmaker(e, class_=AsyncSession, expire_on_commit=False)

    monkeypatch.setattr(agent_tasks, "_make_engine_and_session", _make)
    engine, session = _make()
    yield session
    await engine.dispose()


def _run(status: str, seen: datetime) -> AiAgentRun:
    return AiAgentRun(
        scan_id="scan-1", status=status, mode="autonomous", objective="x",
        last_heartbeat=seen, created_at=seen,
    )


async def _statuses(session) -> dict[str, str]:
    async with session() as db:
        rows = (await db.execute(select(AiAgentRun.id, AiAgentRun.status))).all()
    return {row[0]: row[1] for row in rows}


async def test_queued_run_waiting_behind_live_agent_is_not_reaped(reaper_db):
    now = datetime.now(tz=timezone.utc)
    live, waiting = _run("running", now), _run("queued", now - timedelta(hours=3))
    async with reaper_db() as db:
        db.add_all([live, waiting])
        await db.commit()

    await agent_tasks._reap_stale_agent_runs_async()

    statuses = await _statuses(reaper_db)
    assert statuses[live.id] == "running"
    assert statuses[waiting.id] == "queued"


async def test_lost_queued_run_and_dead_worker_are_reaped(reaper_db):
    old = datetime.now(tz=timezone.utc) - timedelta(hours=3)
    dead, lost = _run("running", old), _run("queued", old)
    async with reaper_db() as db:
        db.add_all([dead, lost])
        await db.commit()

    result = await agent_tasks._reap_stale_agent_runs_async()

    assert result == {"reaped": 2}
    statuses = await _statuses(reaper_db)
    assert statuses[dead.id] == "failed"
    assert statuses[lost.id] == "failed"
