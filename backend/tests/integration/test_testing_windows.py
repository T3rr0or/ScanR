"""Testing windows enforced at launch, rerun, retest, schedules and mid-scan;
activity log integrity."""
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

CLOSED = {"timezone": "UTC", "days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "00:01",
          "not_after": "2000-01-01"}  # an engagement that ended long ago
OPEN = {"timezone": "UTC", "days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "24:00"}


async def _scan(client, headers, window):
    r = await client.post("/api/v1/scans", headers=headers, json={
        "name": "window", "targets": ["198.51.100.50"], "profile_json": json.dumps({"testing_window": window})})
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.mark.asyncio
async def test_launch_refused_outside_the_window(client, auth_headers, monkeypatch):
    scan_id = await _scan(client, auth_headers, CLOSED)
    r = await client.post(f"/api/v1/scans/{scan_id}/launch", headers=auth_headers)
    assert r.status_code == 409 and "testing window" in r.json()["detail"] and "has ended" in r.json()["detail"]

    from scanr.tasks import scan_tasks
    sent = []
    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", lambda *a, **k: sent.append(a) or type("T", (), {"id": "t"})())
    ok_id = await _scan(client, auth_headers, OPEN)
    r = await client.post(f"/api/v1/scans/{ok_id}/launch", headers=auth_headers)
    assert r.status_code == 202, r.text and sent


@pytest.mark.asyncio
async def test_retest_refused_outside_the_window(client, auth_headers):
    scan_id = await _scan(client, auth_headers, CLOSED)
    fid = (await client.post(f"/api/v1/scans/{scan_id}/findings/manual", headers=auth_headers,
                             json={"title": "t", "description": "d", "host": "198.51.100.50"})).json()["id"]
    r = await client.post(f"/api/v1/findings/{fid}/retest", headers=auth_headers)
    assert r.status_code == 409 and "testing window" in r.json()["detail"]


@pytest.mark.asyncio
async def test_invalid_window_rejected_at_creation(client, auth_headers):
    r = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "bad", "targets": ["198.51.100.51"], "profile_json": json.dumps({"testing_window": {"timezone": "nowhere"}})})
    assert r.status_code == 400 and "time zone" in r.text


@pytest.mark.asyncio
async def test_activity_log_records_and_detects_tampering(client, auth_headers, db):
    from scanr.models import Scan, ScanStatus
    from scanr.models.scan_activity import ScanActivity

    scan_id = await _scan(client, auth_headers, OPEN)
    scan = await db.get(Scan, scan_id)
    scan.status = ScanStatus.running
    await db.commit()
    assert (await client.post(f"/api/v1/scans/{scan_id}/pause", headers=auth_headers)).status_code == 202
    assert (await client.post(f"/api/v1/scans/{scan_id}/resume", headers=auth_headers)).status_code == 202
    log = (await client.get(f"/api/v1/scans/{scan_id}/activity", headers=auth_headers)).json()
    assert [e["event"] for e in log["entries"]] == ["paused", "resumed"]
    assert log["verified"] is True and log["entries"][0]["actor"] == "admin@scanr.local"
    assert log["testing_window"] == "every day 00:00–24:00 (UTC)" and log["window_open_now"] is True

    first = (await db.execute(select(ScanActivity).where(ScanActivity.scan_id == scan_id)
                              .order_by(ScanActivity.at))).scalars().first()
    first.detail = "edited afterwards"
    await db.commit()
    assert (await client.get(f"/api/v1/scans/{scan_id}/activity", headers=auth_headers)).json()["verified"] is False


@pytest.mark.asyncio
async def test_schedule_outside_the_window_is_skipped(db):
    from scanr.models import Scan
    from scanr.models.schedule import Schedule
    from scanr.models.user import User
    from scanr.tasks.scheduler_task import _fire_schedule

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    sched = Schedule(user_id=admin.id, name="nightly", targets=json.dumps(["198.51.100.52"]),
                     scan_profile_json=json.dumps({"testing_window": CLOSED}), cron_expr="0 2 * * *", enabled=True)
    db.add(sched)
    await db.commit()
    before = len((await db.execute(select(Scan.id))).all())
    await _fire_schedule(sched, db, datetime.now(timezone.utc))
    assert len((await db.execute(select(Scan.id))).all()) == before
    assert sched.next_run is not None and sched.last_scan_id is None


@pytest.mark.asyncio
async def test_running_scan_pauses_and_resumes_with_the_window(client, auth_headers, db, monkeypatch):
    from scanr.core.context import ScanContext
    from scanr.core.testing_window import TestingWindow
    from scanr.models import Scan, ScanStatus

    scan_id = await _scan(client, auth_headers, OPEN)
    scan = await db.get(Scan, scan_id)
    scan.status = ScanStatus.running
    await db.commit()

    calls = {"n": 0}

    def is_open(self, when=None):
        calls["n"] += 1
        return calls["n"] > 2  # closed for the first two checks, then open

    window = TestingWindow()
    monkeypatch.setattr(TestingWindow, "is_open", is_open)
    seen = []

    async def observe():
        await db.refresh(scan)
        seen.append(scan.status)

    context = ScanContext(scan_id=scan_id, scan=scan, db=db)
    context.testing_window = window
    original_refresh = context.refresh_control_state

    async def refresh():
        await observe()
        await original_refresh()

    context.refresh_control_state = refresh  # type: ignore[method-assign]
    await context.hold_for_testing_window(poll_seconds=0)
    await db.refresh(scan)
    assert seen and seen[0] == ScanStatus.paused
    assert scan.status == ScanStatus.running and scan.error_message is None
    log = (await client.get(f"/api/v1/scans/{scan_id}/activity", headers=auth_headers)).json()
    assert [e["event"] for e in log["entries"]] == ["window_closed", "window_opened"] and log["verified"]
