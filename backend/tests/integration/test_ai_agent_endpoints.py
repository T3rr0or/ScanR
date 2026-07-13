"""Integration tests for the agent's scope confinement and the chat/stop/export
endpoints — areas that previously had no coverage."""
import json

import pytest

from scanr.models import AiAgentRun, Host
from scanr.models.base import new_uuid


async def _make_scan(client, auth_headers, targets):
    resp = await client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={"name": "agent-scope", "targets": targets, "profile": "quick"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_is_in_scope_confines_to_scan(client, auth_headers, db):
    """DbAgentContext.is_in_scope allows the scan's CIDR + discovered hosts and
    denies anything else — validated against a real DB."""
    from scanr.ai.agent.db_context import DbAgentContext
    from scanr.ai.agent.policy import AgentPolicy, AutonomyMode, Budget
    from scanr.core.scan_logger import ScanLogger

    scan_id = await _make_scan(client, auth_headers, ["192.0.2.0/24"])
    # A discovered host outside the target CIDR is still in scope.
    db.add(Host(id=new_uuid(), scan_id=scan_id, ip="10.0.0.5", hostname="box.internal"))
    await db.commit()

    ctx = DbAgentContext(
        scan_id=scan_id,
        db=db,
        policy=AgentPolicy(mode=AutonomyMode.autonomous),
        budget=Budget(),
        denylist=set(),
        logger=ScanLogger(scan_id),
    )
    assert await ctx.is_in_scope("192.0.2.10") is True   # inside target CIDR
    assert await ctx.is_in_scope("10.0.0.5") is True      # discovered host IP
    assert await ctx.is_in_scope("box.internal") is True  # discovered hostname
    assert await ctx.is_in_scope("198.51.100.9") is False  # unrelated third party
    assert await ctx.is_in_scope("evil.example.com") is False


@pytest.mark.asyncio
async def test_agent_collects_web_urls_for_screenshots(client, auth_headers, db):
    """note_web_url dedupes/caps the agent's fetched pages, and flush groups them
    by discovered host without error (capture itself needs Playwright)."""
    from scanr.ai.agent.db_context import DbAgentContext
    from scanr.ai.agent.policy import AgentPolicy, AutonomyMode, Budget
    from scanr.core.scan_logger import ScanLogger

    scan_id = await _make_scan(client, auth_headers, ["192.0.2.30"])
    db.add(Host(id=new_uuid(), scan_id=scan_id, ip="192.0.2.30", hostname=None))
    await db.commit()

    ctx = DbAgentContext(
        scan_id=scan_id,
        db=db,
        policy=AgentPolicy(mode=AutonomyMode.autonomous),
        budget=Budget(),
        denylist=set(),
        logger=ScanLogger(scan_id),
    )
    await ctx.note_web_url("http://192.0.2.30/admin")
    await ctx.note_web_url("http://192.0.2.30/admin")  # duplicate ignored
    await ctx.note_web_url("http://192.0.2.30/login")
    assert ctx._web_urls == ["http://192.0.2.30/admin", "http://192.0.2.30/login"]
    # Must resolve the host and run cleanly even when Playwright is unavailable.
    await ctx.flush_web_screenshots()


def _seed_run(scan_id, status="completed"):
    conv = [
        {"role": "user", "content": "investigate"},
        {
            "role": "assistant",
            "content": "Checking the host.",
            "tool_calls": [{"id": "t1", "name": "fetch_url", "arguments": {"url": "http://192.0.2.10/"}}],
        },
        {"role": "tool", "tool_call_id": "t1", "content": '{"status": 200}'},
        {"role": "assistant", "content": "## Report\nAll done."},
    ]
    return AiAgentRun(
        id=new_uuid(),
        scan_id=scan_id,
        status=status,
        mode="guided",
        objective="investigate",
        provider="anthropic",
        model="claude",
        conversation=json.dumps(conv),
        final_text="## Report\nAll done.",
    )


@pytest.mark.asyncio
async def test_agent_trace_export(client, auth_headers, db):
    scan_id = await _make_scan(client, auth_headers, ["192.0.2.20"])
    run = _seed_run(scan_id)
    db.add(run)
    await db.commit()

    md = await client.get(f"/api/v1/ai/agent/runs/{run.id}/export", headers=auth_headers, params={"format": "md"})
    assert md.status_code == 200
    assert "attachment" in md.headers.get("content-disposition", "")
    body = md.text
    assert "fetch_url" in body and "192.0.2.10" in body and "## Report" in body

    js = await client.get(f"/api/v1/ai/agent/runs/{run.id}/export", headers=auth_headers, params={"format": "json"})
    assert js.status_code == 200
    assert js.json()["id"] == run.id


@pytest.mark.asyncio
async def test_agent_chat_rejects_while_running(client, auth_headers, db):
    scan_id = await _make_scan(client, auth_headers, ["192.0.2.21"])
    run = _seed_run(scan_id, status="running")
    db.add(run)
    await db.commit()

    r = await client.post(
        f"/api/v1/ai/agent/runs/{run.id}/chat", headers=auth_headers, json={"message": "and now?"}
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_agent_stop_noop_when_not_running(client, auth_headers, db):
    scan_id = await _make_scan(client, auth_headers, ["192.0.2.22"])
    run = _seed_run(scan_id, status="completed")
    db.add(run)
    await db.commit()

    r = await client.post(f"/api/v1/ai/agent/runs/{run.id}/stop", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["id"] == run.id
