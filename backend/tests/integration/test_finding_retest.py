"""Finding retest: request, guard rails, history, and the full task run."""
import pytest
from sqlalchemy import delete as sa_delete, select


@pytest.fixture
async def finding_fixture(db):
    """A completed scan with one host and one finding from a real plugin id."""
    from scanr.models import Finding, Host, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    scan = Scan(id=new_uuid(), name="retest-scan", status=ScanStatus.completed,
                profile="standard", user_id=admin.id)
    db.add(scan)
    await db.flush()
    host = Host(id=new_uuid(), scan_id=scan.id, ip="192.0.2.40", hostname="ftp01", status="up")
    db.add(host)
    await db.flush()
    finding = Finding(
        id=new_uuid(), scan_id=scan.id, host_id=host.id,
        plugin_id="services.ftp_anon", severity="high",
        title="Anonymous FTP login allowed", port_number=21,
    )
    db.add(finding)
    await db.commit()

    yield {"scan_id": scan.id, "host_id": host.id, "finding_id": finding.id}

    from scanr.models import FindingRetest
    await db.execute(sa_delete(FindingRetest).where(FindingRetest.finding_id == finding.id))
    await db.execute(sa_delete(Finding).where(Finding.scan_id == scan.id))
    await db.execute(sa_delete(Host).where(Host.scan_id == scan.id))
    await db.execute(sa_delete(Scan).where(Scan.id == scan.id))
    await db.commit()


@pytest.fixture(autouse=True)
def no_celery(monkeypatch):
    """Queue nothing: these tests exercise the endpoint, not the worker."""
    import scanr.tasks.retest_tasks as rt

    monkeypatch.setattr(rt.retest_finding_task, "delay", lambda *a, **kw: None)


@pytest.mark.asyncio
async def test_requesting_a_retest_queues_one(client, auth_headers, finding_fixture):
    r = await client.post(f"/api/v1/findings/{finding_fixture['finding_id']}/retest",
                          headers=auth_headers)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["verdict"] is None


@pytest.mark.asyncio
async def test_concurrent_retests_are_refused(client, auth_headers, finding_fixture):
    """Two runs would race to write the verdict."""
    fid = finding_fixture["finding_id"]
    assert (await client.post(f"/api/v1/findings/{fid}/retest", headers=auth_headers)).status_code == 202
    second = await client.post(f"/api/v1/findings/{fid}/retest", headers=auth_headers)
    assert second.status_code == 409, second.text


@pytest.mark.asyncio
async def test_retest_needs_triage_not_just_read(client, auth_headers, finding_fixture, db):
    """It sends live traffic to the host, so read access is not enough."""
    created = await client.post("/api/v1/users", headers=auth_headers, json={
        "email": "viewer-retest@scanr.local", "password": "viewerretest123", "role": "viewer",
    })
    uid = created.json()["id"]
    login = await client.post("/api/v1/auth/login", json={
        "email": "viewer-retest@scanr.local", "password": "viewerretest123",
    })
    viewer = {"Authorization": f"Bearer {login.json()['access_token']}"}

    r = await client.post(f"/api/v1/findings/{finding_fixture['finding_id']}/retest",
                          headers=viewer)
    assert r.status_code == 403, r.text

    await client.delete(f"/api/v1/users/{uid}", headers=auth_headers)


@pytest.mark.asyncio
async def test_another_users_finding_is_not_retestable(client, auth_headers, finding_fixture):
    created = await client.post("/api/v1/users", headers=auth_headers, json={
        "email": "other-retest@scanr.local", "password": "otherretest123", "role": "analyst",
    })
    uid = created.json()["id"]
    login = await client.post("/api/v1/auth/login", json={
        "email": "other-retest@scanr.local", "password": "otherretest123",
    })
    other = {"Authorization": f"Bearer {login.json()['access_token']}"}

    r = await client.post(f"/api/v1/findings/{finding_fixture['finding_id']}/retest",
                          headers=other)
    assert r.status_code == 404, r.text

    await client.delete(f"/api/v1/users/{uid}", headers=auth_headers)


@pytest.mark.asyncio
async def test_unknown_plugin_is_rejected_with_a_reason(client, auth_headers, db, finding_fixture):
    """A finding imported from another tool has no plugin to re-run; say so
    rather than queueing a job that can only fail."""
    from scanr.models import Finding

    finding = await db.get(Finding, finding_fixture["finding_id"])
    finding.plugin_id = "does.not.exist"
    await db.commit()

    r = await client.post(f"/api/v1/findings/{finding.id}/retest", headers=auth_headers)
    assert r.status_code == 400, r.text
    assert "not available" in r.json()["detail"]


@pytest.mark.asyncio
async def test_hostless_finding_is_rejected(client, auth_headers, db, finding_fixture):
    from scanr.models import Finding

    finding = await db.get(Finding, finding_fixture["finding_id"])
    finding.host_id = None
    await db.commit()

    r = await client.post(f"/api/v1/findings/{finding.id}/retest", headers=auth_headers)
    assert r.status_code == 400, r.text
    assert "not attached to a host" in r.json()["detail"]


@pytest.mark.asyncio
async def test_history_is_newest_first(client, auth_headers, db, finding_fixture):
    """The evidence trail: 'still present on the 12th, fixed on the 3rd'."""
    from datetime import datetime, timedelta, timezone

    from scanr.models import FindingRetest
    from scanr.models.base import new_uuid

    fid = finding_fixture["finding_id"]
    # Explicit, distinct timestamps: created_at has second resolution, so two
    # rows inserted back to back would tie and prove nothing about ordering.
    base = datetime.now(timezone.utc)
    for offset, verdict in ((timedelta(days=-9), "still_present"), (timedelta(0), "resolved")):
        db.add(FindingRetest(id=new_uuid(), finding_id=fid, status="completed",
                             verdict=verdict, evidence=f"run said {verdict}",
                             created_at=base + offset))
        await db.commit()

    r = await client.get(f"/api/v1/findings/{fid}/retests", headers=auth_headers)
    assert r.status_code == 200, r.text
    rows = r.json()
    assert len(rows) == 2
    assert [x["verdict"] for x in rows] == ["resolved", "still_present"]


@pytest.mark.asyncio
async def test_latest_verdict_appears_on_the_finding(client, auth_headers, db, finding_fixture):
    """So the findings list can show verification state without N+1 requests."""
    from datetime import datetime, timezone

    from scanr.models import Finding

    finding = await db.get(Finding, finding_fixture["finding_id"])
    finding.last_retest_verdict = "resolved"
    finding.last_retest_at = datetime.now(timezone.utc)
    await db.commit()

    r = await client.get(f"/api/v1/findings/{finding.id}", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["last_retest_verdict"] == "resolved"
    assert r.json()["last_retest_at"] is not None


# ── the worker path ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_task_records_still_present_and_updates_the_finding(
    monkeypatch, db, finding_fixture
):
    """Full run against a stubbed plugin that still reports the issue."""
    from scanr.core import plugin_manager
    from scanr.models import Finding, FindingRetest
    from scanr.models.base import new_uuid
    import scanr.tasks.retest_tasks as rt

    class _Observed:
        severity = "high"
        title = "Anonymous FTP login allowed"
        evidence = "230 Login successful."
        port_number = 21

    class _StubPlugin:
        async def check(self, ctx, host):
            return [_Observed()]

    monkeypatch.setattr(plugin_manager, "get_all_plugin_classes",
                        lambda: {"services.ftp_anon": _StubPlugin})
    # The task opens its own session/engine; point it at the test one.
    import scanr.db.session as session_module
    monkeypatch.setattr(rt, "_make_engine_and_session",
                        lambda: (_NullEngine(), session_module.AsyncSessionLocal))

    retest = FindingRetest(id=new_uuid(), finding_id=finding_fixture["finding_id"],
                           status="pending")
    db.add(retest)
    await db.commit()

    result = await rt._run_retest(retest.id)
    assert result == {"status": "completed", "verdict": "still_present"}

    async with session_module.AsyncSessionLocal() as fresh:
        stored = await fresh.get(FindingRetest, retest.id)
        assert stored.status == "completed"
        assert stored.verdict == "still_present"
        assert "230 Login successful" in stored.evidence
        finding = await fresh.get(Finding, finding_fixture["finding_id"])
        assert finding.last_retest_verdict == "still_present"
        assert finding.last_retest_at is not None


@pytest.mark.asyncio
async def test_task_records_resolved_when_the_plugin_reports_nothing(
    monkeypatch, db, finding_fixture
):
    from scanr.core import plugin_manager
    from scanr.models import FindingRetest
    from scanr.models.base import new_uuid
    import scanr.db.session as session_module
    import scanr.tasks.retest_tasks as rt

    class _StubPlugin:
        async def check(self, ctx, host):
            return []

    monkeypatch.setattr(plugin_manager, "get_all_plugin_classes",
                        lambda: {"services.ftp_anon": _StubPlugin})
    monkeypatch.setattr(rt, "_make_engine_and_session",
                        lambda: (_NullEngine(), session_module.AsyncSessionLocal))

    retest = FindingRetest(id=new_uuid(), finding_id=finding_fixture["finding_id"],
                           status="pending")
    db.add(retest)
    await db.commit()

    result = await rt._run_retest(retest.id)
    assert result["verdict"] == "resolved"


@pytest.mark.asyncio
async def test_task_marks_failed_when_the_plugin_raises(monkeypatch, db, finding_fixture):
    """A crashing plugin is a failed retest, not a lost task — and definitely
    not a 'resolved' verdict."""
    from scanr.core import plugin_manager
    from scanr.models import Finding, FindingRetest
    from scanr.models.base import new_uuid
    import scanr.db.session as session_module
    import scanr.tasks.retest_tasks as rt

    class _Boom:
        async def check(self, ctx, host):
            raise RuntimeError("connection reset")

    monkeypatch.setattr(plugin_manager, "get_all_plugin_classes",
                        lambda: {"services.ftp_anon": _Boom})
    monkeypatch.setattr(rt, "_make_engine_and_session",
                        lambda: (_NullEngine(), session_module.AsyncSessionLocal))

    retest = FindingRetest(id=new_uuid(), finding_id=finding_fixture["finding_id"],
                           status="pending")
    db.add(retest)
    await db.commit()

    result = await rt._run_retest(retest.id)
    assert result["status"] == "failed"

    async with session_module.AsyncSessionLocal() as fresh:
        stored = await fresh.get(FindingRetest, retest.id)
        assert stored.status == "failed"
        assert stored.verdict is None, "a crash must never imply a verdict"
        assert "connection reset" in stored.error
        finding = await fresh.get(Finding, finding_fixture["finding_id"])
        assert finding.last_retest_verdict is None


@pytest.mark.asyncio
async def test_task_is_inconclusive_when_the_host_is_down(monkeypatch, db, finding_fixture):
    """The important one: a host that is merely switched off must not be
    reported as remediated."""
    from scanr.core import plugin_manager
    from scanr.models import FindingRetest, Host
    from scanr.models.base import new_uuid
    import scanr.db.session as session_module
    import scanr.tasks.retest_tasks as rt

    host = await db.get(Host, finding_fixture["host_id"])
    host.status = "down"
    await db.commit()

    class _StubPlugin:
        async def check(self, ctx, host):
            return []

    monkeypatch.setattr(plugin_manager, "get_all_plugin_classes",
                        lambda: {"services.ftp_anon": _StubPlugin})
    monkeypatch.setattr(rt, "_make_engine_and_session",
                        lambda: (_NullEngine(), session_module.AsyncSessionLocal))

    retest = FindingRetest(id=new_uuid(), finding_id=finding_fixture["finding_id"],
                           status="pending")
    db.add(retest)
    await db.commit()

    result = await rt._run_retest(retest.id)
    assert result["verdict"] == "inconclusive"


class _NullEngine:
    """Stand-in for the task's own engine; the test session owns the real one."""

    async def dispose(self):
        return None
