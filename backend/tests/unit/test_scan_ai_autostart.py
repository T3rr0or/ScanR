"""Unit tests for scan-creation AI opt-in wiring (slices A + B)."""
import types

import pytest

from scanr.ai.agent import autostart


@pytest.mark.asyncio
async def test_build_scan_agent_run_disabled_returns_none():
    # A scan that didn't opt into AI never builds a run (and never touches the DB).
    scan = types.SimpleNamespace(id="s1", ai_agent_enabled=False)
    assert await autostart.build_scan_agent_run(db=None, scan=scan) is None


@pytest.mark.asyncio
async def test_build_scan_agent_run_missing_attr_returns_none():
    # Defensive: an object without the attribute is treated as disabled.
    assert await autostart.build_scan_agent_run(db=None, scan=object()) is None
