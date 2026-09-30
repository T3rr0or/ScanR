"""Update coordination, responsiveness and truthful restart status."""
import asyncio
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import BackgroundTasks, HTTPException

from scanr.api.v1 import system


@pytest.fixture
def redis(monkeypatch):
    values = {}

    async def set_value(key, value, **kwargs):
        if kwargs.get('nx') and key in values:
            return False
        values[key] = value
        return True

    async def setex(key, ttl, value):
        values[key] = value

    async def delete(key):
        values.pop(key, None)

    client = SimpleNamespace(
        set=AsyncMock(side_effect=set_value),
        setex=AsyncMock(side_effect=setex),
        get=AsyncMock(side_effect=lambda key: values.get(key)),
        exists=AsyncMock(side_effect=lambda key: key in values),
        eval=AsyncMock(),
        delete=AsyncMock(side_effect=delete),
        values=values,
    )
    monkeypatch.setattr('scanr.db.redis.get_redis', lambda: client)
    monkeypatch.setattr(system.settings, 'self_update_enabled', True)
    return client


@pytest.mark.asyncio
async def test_two_requests_cannot_queue_two_updates(redis):
    results = await asyncio.gather(
        system.start_update(BackgroundTasks(), None),
        system.start_update(BackgroundTasks(), None),
        return_exceptions=True,
    )
    assert sum(isinstance(r, HTTPException) and r.status_code == 409 for r in results) == 1
    assert sum(isinstance(r, dict) and r['state'] == 'queued' for r in results) == 1


@pytest.mark.asyncio
async def test_status_cannot_be_cleared_during_live_update(redis):
    await system.start_update(BackgroundTasks(), None)
    with pytest.raises(HTTPException) as exc:
        await system.reset_update_status(None)
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_redis_outage_fails_closed(redis):
    redis.set.side_effect = RuntimeError('offline')
    tasks = BackgroundTasks()
    with pytest.raises(HTTPException) as exc:
        await system.start_update(tasks, None)
    assert exc.value.status_code == 503
    assert not tasks.tasks


@pytest.mark.asyncio
async def test_restart_failure_is_not_reported_success(redis, monkeypatch, tmp_path):
    monkeypatch.setattr(system.settings, 'self_update_workdir', tmp_path)
    monkeypatch.setattr(system.settings, 'self_update_command', 'docker compose pull && docker compose up -d')
    seen = []

    def run(argv, **kwargs):
        seen.append(kwargs['env'])
        return subprocess.CompletedProcess(argv, 1 if 'up' in argv else 0, 'result')

    monkeypatch.setattr(system.subprocess, 'run', run)
    await system._run_self_update('token')
    states = [json.loads(c.args[2])['state'] for c in redis.setex.call_args_list]
    assert 'restarting' in states
    assert 'succeeded' not in states
    assert states[-1] == 'failed'
    assert all('SCANR_VERSION' not in env for env in seen)
    assert all('SECRET_KEY' not in env for env in seen)


@pytest.mark.asyncio
async def test_blocking_command_runs_outside_event_loop(redis, monkeypatch, tmp_path):
    import threading
    monkeypatch.setattr(system.settings, 'self_update_workdir', tmp_path)
    monkeypatch.setattr(system.settings, 'self_update_command', 'docker compose pull')
    event_loop_thread = threading.get_ident()

    def run(argv, **kwargs):
        assert threading.get_ident() != event_loop_thread
        return subprocess.CompletedProcess(argv, 0, 'done')

    monkeypatch.setattr(system.subprocess, 'run', run)
    await system._run_self_update('token')
    assert (await system._get_update_status())['state'] == 'succeeded'


async def _status_from(redis, state, instance):
    await system._set_update_status({
        'state': state, 'api_instance': instance,
        'started_at': system._utc_now(), 'message': None, 'log': '',
    })
    redis.values[system.UPDATE_LOCK_KEY] = 'token'
    return await system._get_update_status()


@pytest.mark.asyncio
async def test_replacement_api_verifies_restart_and_releases_lock(redis):
    status = await _status_from(redis, 'restarting', 'previous-api')
    assert status['state'] == 'succeeded'
    assert system.settings.app_version in status['message']
    assert system.UPDATE_LOCK_KEY not in redis.values


@pytest.mark.asyncio
async def test_api_restart_mid_pull_fails_immediately_and_releases_lock(redis):
    status = await _status_from(redis, 'running', 'previous-api')
    assert status['state'] == 'failed'
    assert system.UPDATE_LOCK_KEY not in redis.values


@pytest.mark.asyncio
async def test_same_api_leaves_in_progress_update_alone(redis):
    status = await _status_from(redis, 'restarting', system._API_INSTANCE)
    assert status['state'] == 'restarting'
    assert system.UPDATE_LOCK_KEY in redis.values
