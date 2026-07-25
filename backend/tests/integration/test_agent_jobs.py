"""Remote scan-agent job endpoints: bounds and single-submission semantics.

These endpoints are authenticated by an X-Agent-Token held on a remote host we
do not control, so the payload is untrusted: lists must be bounded, strings must
fit their columns, and results must only be accepted once for a running scan.
Re-submitting used to append duplicate hosts/findings and re-increment the
severity counters.
"""
import hashlib

import pytest
from sqlalchemy import delete as sa_delete
from sqlalchemy import select

from scanr.models.scan_agent import ScanAgent

AGENT_TOKEN = "test-agent-token-abcdef0123456789"


@pytest.fixture
async def agent_scan(db, auth_headers, client):
    """A registered agent plus a pending scan assigned to it."""
    from scanr.models import Scan, ScanStatus, Target
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()

    agent = ScanAgent(
        id=new_uuid(),
        user_id=admin.id,
        name="test-agent",
        token_hash=hashlib.sha256(AGENT_TOKEN.encode()).hexdigest(),
        prefix=AGENT_TOKEN[:12],
        enabled=True,
    )
    db.add(agent)
    await db.flush()  # scans.agent_id is an FK — the agent row must exist first

    scan = Scan(
        id=new_uuid(), name="agent-job-scan", status=ScanStatus.pending,
        profile="standard", user_id=admin.id, agent_id=agent.id,
    )
    db.add(scan)
    await db.flush()
    db.add(Target(id=new_uuid(), scan_id=scan.id, value="192.0.2.30", type="ip"))
    await db.commit()

    agent_id, scan_id = agent.id, scan.id
    yield {"agent_id": agent_id, "scan_id": scan_id, "headers": {"X-Agent-Token": AGENT_TOKEN}}

    # Tear down child-first so FK constraints hold, and commit the scan delete
    # before the agent it references.
    await _purge_scan(db, scan_id)
    await db.execute(sa_delete(ScanAgent).where(ScanAgent.id == agent_id))
    await db.commit()


async def _purge_scan(db, scan_id: str) -> None:
    from scanr.models import Finding, Host, Port, Scan, Service, Target

    host_ids = (await db.execute(select(Host.id).where(Host.scan_id == scan_id))).scalars().all()
    if host_ids:
        port_ids = (
            await db.execute(select(Port.id).where(Port.host_id.in_(host_ids)))
        ).scalars().all()
        if port_ids:
            await db.execute(sa_delete(Service).where(Service.port_id.in_(port_ids)))
            await db.execute(sa_delete(Port).where(Port.id.in_(port_ids)))
    await db.execute(sa_delete(Finding).where(Finding.scan_id == scan_id))
    await db.execute(sa_delete(Host).where(Host.scan_id == scan_id))
    await db.execute(sa_delete(Target).where(Target.scan_id == scan_id))
    await db.execute(sa_delete(Scan).where(Scan.id == scan_id))
    await db.commit()


@pytest.mark.asyncio
async def test_start_then_submit_then_resubmit_conflicts(client, agent_scan):
    sid, headers = agent_scan["scan_id"], agent_scan["headers"]

    assert (await client.post(f"/api/v1/agent/jobs/{sid}/start", headers=headers)).status_code == 200

    payload = {
        "hosts": [{"ip": "192.0.2.30", "status": "up",
                   "ports": [{"number": 80, "protocol": "tcp", "state": "open"}]}],
        "findings": [{"host_ip": "192.0.2.30", "plugin_id": "web.test",
                      "severity": "high", "title": "test finding"}],
    }
    first = await client.post(f"/api/v1/agent/jobs/{sid}/results", headers=headers, json=payload)
    assert first.status_code == 200, first.text
    assert first.json() == {"status": "ok", "hosts": 1, "findings": 1}

    # Second submission must be refused, not silently duplicated.
    second = await client.post(f"/api/v1/agent/jobs/{sid}/results", headers=headers, json=payload)
    assert second.status_code == 409, second.text


@pytest.mark.asyncio
async def test_cannot_restart_a_finished_scan(client, agent_scan, db):
    sid, headers = agent_scan["scan_id"], agent_scan["headers"]
    await client.post(f"/api/v1/agent/jobs/{sid}/start", headers=headers)
    await client.post(f"/api/v1/agent/jobs/{sid}/results", headers=headers,
                      json={"hosts": [], "findings": []})

    reopened = await client.post(f"/api/v1/agent/jobs/{sid}/start", headers=headers)
    assert reopened.status_code == 409, reopened.text


@pytest.mark.asyncio
async def test_submitting_without_start_conflicts(client, agent_scan):
    """A pending (not running) scan must not accept results."""
    sid, headers = agent_scan["scan_id"], agent_scan["headers"]
    r = await client.post(f"/api/v1/agent/jobs/{sid}/results", headers=headers,
                          json={"hosts": [], "findings": []})
    assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_duplicate_ips_collapse_to_one_host(client, agent_scan, auth_headers):
    sid, headers = agent_scan["scan_id"], agent_scan["headers"]
    await client.post(f"/api/v1/agent/jobs/{sid}/start", headers=headers)

    r = await client.post(f"/api/v1/agent/jobs/{sid}/results", headers=headers, json={
        "hosts": [
            {"ip": "192.0.2.30", "status": "up"},
            {"ip": "192.0.2.30", "status": "up"},
            {"ip": "192.0.2.31", "status": "down"},
        ],
        "findings": [],
    })
    assert r.status_code == 200, r.text
    assert r.json()["hosts"] == 2, "duplicate IPs must collapse"

    # The scan's counters must match the rows actually stored, not the payload.
    detail = await client.get(f"/api/v1/scans/{sid}", headers=auth_headers)
    assert detail.status_code == 200, detail.text
    assert detail.json()["hosts_total"] == 2
    assert detail.json()["hosts_up"] == 1  # 192.0.2.30 up, 192.0.2.31 down


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_payload,reason", [
    ({"hosts": [{"ip": "192.0.2.30", "ports": [{"number": 99999}]}], "findings": []}, "port out of range"),
    ({"hosts": [{"ip": "192.0.2.30", "ports": [{"number": 0}]}], "findings": []}, "port zero"),
    ({"hosts": [{"ip": "192.0.2.30", "hostname": "h" * 300}], "findings": []}, "hostname over column width"),
    ({"hosts": [{"ip": "192.0.2.30", "status": "weird"}], "findings": []}, "status not in enum"),
    ({"hosts": [{"ip": "192.0.2.30", "ports": [{"number": 80, "protocol": "x" * 20}]}], "findings": []}, "protocol"),
    ({"hosts": [{"ip": "not-an-ip"}], "findings": []}, "invalid ip"),
    ({"hosts": [], "findings": [{"host_ip": "192.0.2.30", "plugin_id": "p",
                                 "severity": "high", "title": "t",
                                 "protocol": "toolongproto"}]}, "finding protocol width"),
])
async def test_malformed_results_rejected(client, agent_scan, bad_payload, reason):
    sid, headers = agent_scan["scan_id"], agent_scan["headers"]
    await client.post(f"/api/v1/agent/jobs/{sid}/start", headers=headers)
    r = await client.post(f"/api/v1/agent/jobs/{sid}/results", headers=headers, json=bad_payload)
    assert r.status_code == 422, f"{reason}: expected 422, got {r.status_code} {r.text}"


@pytest.mark.asyncio
async def test_oversized_host_list_rejected(client, agent_scan):
    sid, headers = agent_scan["scan_id"], agent_scan["headers"]
    await client.post(f"/api/v1/agent/jobs/{sid}/start", headers=headers)
    r = await client.post(f"/api/v1/agent/jobs/{sid}/results", headers=headers, json={
        "hosts": [{"ip": f"10.0.{i // 256}.{i % 256}"} for i in range(5000)],
        "findings": [],
    })
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_invalid_agent_token_rejected(client, agent_scan):
    sid = agent_scan["scan_id"]
    r = await client.post(f"/api/v1/agent/jobs/{sid}/start", headers={"X-Agent-Token": "wrong"})
    assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_agent_cannot_touch_another_agents_scan(client, agent_scan, db, auth_headers):
    """Scans are matched on (scan_id, agent_id) — a valid token for agent B must
    not be able to start or fail agent A's job."""
    from scanr.models.base import new_uuid
    from scanr.models.scan_agent import ScanAgent
    from scanr.models.user import User
    from sqlalchemy import select

    other_token = "other-agent-token-9876543210fedcba"
    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    other = ScanAgent(
        id=new_uuid(), user_id=admin.id, name="other-agent",
        token_hash=hashlib.sha256(other_token.encode()).hexdigest(),
        prefix=other_token[:12], enabled=True,
    )
    db.add(other)
    await db.commit()

    sid = agent_scan["scan_id"]
    r = await client.post(f"/api/v1/agent/jobs/{sid}/start",
                          headers={"X-Agent-Token": other_token})
    assert r.status_code == 404, r.text

    await db.delete(other)
    await db.commit()
