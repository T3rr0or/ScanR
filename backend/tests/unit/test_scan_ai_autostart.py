"""Unit tests for scan-creation AI opt-in wiring (slices A + B)."""
import types
import inspect

import pytest

from scanr.ai.agent import autostart
from scanr.core.engine import ScanEngine


@pytest.mark.asyncio
async def test_build_scan_agent_run_disabled_returns_none():
    # A scan that didn't opt into AI never builds a run (and never touches the DB).
    scan = types.SimpleNamespace(id="s1", ai_agent_enabled=False)
    assert await autostart.build_scan_agent_run(db=None, scan=scan) is None


@pytest.mark.asyncio
async def test_build_scan_agent_run_missing_attr_returns_none():
    # Defensive: an object without the attribute is treated as disabled.
    assert await autostart.build_scan_agent_run(db=None, scan=object()) is None


@pytest.mark.asyncio
async def test_scan_worker_build_does_not_resolve_provider_secret(monkeypatch):
    async def forbidden_secret_resolution(*_args, **_kwargs):
        raise AssertionError("scan worker must not resolve provider credentials")

    class FakeDb:
        def __init__(self):
            self.added = None

        def add(self, row):
            self.added = row

        async def commit(self):
            return None

    monkeypatch.setattr(
        "scanr.ai.settings_store.resolve_api_key",
        forbidden_secret_resolution,
    )
    scan = types.SimpleNamespace(
        id="s1",
        ai_agent_enabled=True,
        ai_agent_provider="openai",
        ai_agent_mode="guided",
        ai_agent_objective="",
        ai_agent_model=None,
        ai_agent_capabilities=None,
    )
    db = FakeDb()

    run = await autostart.build_scan_agent_run(
        db,
        scan,
        validate_api_key=False,
    )

    assert run is db.added
    assert run.provider == "openai"
    assert run.status == "queued"


@pytest.mark.asyncio
async def test_manual_build_still_requires_provider_secret(monkeypatch):
    async def missing_secret(*_args, **_kwargs):
        return ""

    monkeypatch.setattr("scanr.ai.settings_store.resolve_api_key", missing_secret)
    scan = types.SimpleNamespace(
        id="s1",
        ai_agent_enabled=True,
        ai_agent_provider="openai",
    )

    assert await autostart.build_scan_agent_run(db=object(), scan=scan) is None


def test_scan_worker_only_enqueues_agent_on_isolated_queue():
    source = inspect.getsource(ScanEngine._run_ai_phase)
    assert "_run_agent_async" not in source
    assert 'apply_async(args=[run.id], queue="ai")' in source
    assert "validate_api_key=False" in source
    assert "resolve_api_key" not in source
