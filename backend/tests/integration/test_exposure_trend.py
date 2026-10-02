"""Exposure trend: issue lifecycle across scans, SLA and time-to-fix."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete as sa_delete, select

from scanr.core.exposure import Issue, summarize

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
SLA = {"critical": 15, "high": 30, "medium": 90, "low": 180}


def _issue(sev="high", age=10, closed=None, how="fixed", priority=None, kev=False):
    first = NOW - timedelta(days=age)
    return Issue(title=f"{sev}-{age}", ip="10.0.0.1", port=443, severity=sev, first_seen=first, last_seen=first,
                 priority=priority, kev=kev,
                 closed_at=None if closed is None else NOW - timedelta(days=closed),
                 closed_how=None if closed is None else how)


def test_summary_counts_open_overdue_and_time_to_fix():
    issues = [
        _issue("critical", age=40, priority=90, kev=True),          # open, overdue (40 > 15)
        _issue("critical", age=5),                                   # open, within SLA
        _issue("high", age=20, closed=10),                           # fixed in 10 days
        _issue("high", age=60, closed=5),                            # fixed in 55 days: late
        _issue("medium", age=30, closed=2, how="accepted"),          # accepted: not "fixed"
    ]
    out = summarize(issues, weeks=4, sla_days=SLA, now=NOW)
    crit, high = out["by_severity"]["critical"], out["by_severity"]["high"]
    assert crit["open"] == 2 and crit["overdue"] == 1 and crit["fixed"] == 0
    assert high["open"] == 0 and high["fixed"] == 2
    assert high["mean_days_to_fix"] == 32.5 and high["median_days_to_fix"] == 32.5
    assert high["fixed_within_sla"] == 0.5
    assert out["by_severity"]["medium"]["open"] == 0 and out["by_severity"]["medium"]["fixed"] == 0

    last = out["points"][-1]
    assert last["critical"] == 2 and last["fix_now"] == 1 and last["kev"] == 1
    assert last["new"] == 1 and last["fixed"] == 1        # in the last 7 days
    two_weeks_ago = out["points"][-3]
    assert two_weeks_ago["high"] == 2                     # both highs were open then
    assert out["points"][-4]["high"] == 1                 # one did not exist yet
    assert len(out["points"]) == 5
    assert [o["title"] for o in out["overdue"]] == ["critical-40"]


@pytest.fixture
async def history(db):
    """Two scans of one host. Scan 2 ran plugin 'fixedcheck' successfully and
    no longer reports it; it did not run 'skipped', so that one stays open."""
    from scanr.models import Finding, Host, PluginRun, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    now = datetime.now(timezone.utc)
    s1, s2, h1, h2 = new_uuid(), new_uuid(), new_uuid(), new_uuid()
    ip = "198.18.7.7"
    db.add_all([
        Scan(id=s1, name="w1", status=ScanStatus.completed, profile="standard", user_id=admin.id),
        Scan(id=s2, name="w2", status=ScanStatus.completed, profile="standard", user_id=admin.id),
    ])
    await db.flush()
    db.add_all([Host(id=h1, scan_id=s1, ip=ip, status="up"), Host(id=h2, scan_id=s2, ip=ip, status="up")])
    await db.flush()
    from scanr.models import Plugin
    for pid in ("trend.fixedcheck", "trend.skipped", "trend.persisting", "trend.fp"):
        if not (await db.execute(select(Plugin).where(Plugin.id == pid))).scalar_one_or_none():
            db.add(Plugin(id=pid, name=pid, category="web", description="", default_severity="info", enabled=True))
    await db.flush()

    def finding(scan, host, plugin, sev, days_ago, **kw):
        return Finding(id=new_uuid(), scan_id=scan, host_id=host, plugin_id=plugin, severity=sev,
                       title=f"{plugin} issue", port_number=443,
                       created_at=now - timedelta(days=days_ago), **kw)

    db.add_all([
        finding(s1, h1, "trend.fixedcheck", "critical", 20),
        finding(s1, h1, "trend.skipped", "high", 20),
        finding(s1, h1, "trend.persisting", "medium", 20),
        finding(s2, h2, "trend.persisting", "medium", 3),
        finding(s1, h1, "trend.fp", "high", 20),
        finding(s2, h2, "trend.fp", "high", 3, false_positive=True),
        PluginRun(id=new_uuid(), scan_id=s2, host_id=h2, host_ip=ip, plugin_id="trend.fixedcheck",
                  status="success", created_at=now - timedelta(days=3)),
        PluginRun(id=new_uuid(), scan_id=s2, host_id=h2, host_ip=ip, plugin_id="trend.persisting",
                  status="success", created_at=now - timedelta(days=3)),
    ])
    await db.commit()
    yield ip
    await db.execute(sa_delete(PluginRun).where(PluginRun.scan_id.in_([s1, s2])))
    await db.execute(sa_delete(Finding).where(Finding.scan_id.in_([s1, s2])))
    await db.execute(sa_delete(Host).where(Host.scan_id.in_([s1, s2])))
    await db.execute(sa_delete(Scan).where(Scan.id.in_([s1, s2])))
    await db.commit()


@pytest.mark.asyncio
async def test_lifecycle_from_scans(db, history):
    from scanr.core.exposure import load_issues
    from scanr.models.user import User

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    issues = {i.title: i for i in await load_issues(db, admin.id) if i.ip == history}
    assert set(issues) == {"trend.fixedcheck issue", "trend.skipped issue", "trend.persisting issue"}
    assert issues["trend.fixedcheck issue"].closed_how == "fixed"
    assert round((issues["trend.fixedcheck issue"].closed_at - issues["trend.fixedcheck issue"].first_seen).days) == 17
    assert issues["trend.skipped issue"].closed_at is None          # check never re-ran
    assert issues["trend.persisting issue"].closed_at is None        # re-run still found it


@pytest.mark.asyncio
async def test_endpoint(client, auth_headers, history):
    r = await client.get("/api/v1/analytics/exposure-trend?weeks=4", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["points"]) == 5 and body["by_severity"]["critical"]["sla_days"] == 15
    assert body["by_severity"]["critical"]["fixed"] >= 1
    # Open for 20 days: inside the 30-day high SLA, so not overdue.
    assert all(o["title"] != "trend.skipped issue" for o in body["overdue"])
    assert (await client.get("/api/v1/analytics/exposure-trend?weeks=2", headers=auth_headers)).status_code == 422


def test_sla_setting_parsing():
    from scanr.config import _parse_sla

    assert _parse_sla("critical=7, high=14") == {"critical": 7, "high": 14, "medium": 90, "low": 180}
    with pytest.raises(ValueError):
        _parse_sla("urgent=3")
    with pytest.raises(ValueError):
        _parse_sla("critical=0")
