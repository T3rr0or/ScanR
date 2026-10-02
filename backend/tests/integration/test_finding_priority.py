"""Fix-first priority: stored scores, API sorting and re-ranking triggers."""
import json

import pytest
from sqlalchemy import delete as sa_delete, select


@pytest.fixture
async def ranked(db, monkeypatch):
    from scanr.core import priority_service
    from scanr.models import Finding, Host, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    async def fake_threat_data(cves):
        return {"CVE-2099-0001": (0.64, 0.99)}, frozenset({"CVE-2099-0002"})

    monkeypatch.setattr(priority_service, "_threat_data", fake_threat_data)

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    scan = Scan(id=new_uuid(), name="prio", status=ScanStatus.completed, profile="standard", user_id=admin.id)
    db.add(scan)
    await db.flush()
    internal = Host(id=new_uuid(), scan_id=scan.id, ip="10.20.30.40", status="up")
    public = Host(id=new_uuid(), scan_id=scan.id, ip="93.184.216.34", status="up")
    db.add_all([internal, public])
    await db.flush()
    findings = {
        "theoretical": Finding(id=new_uuid(), scan_id=scan.id, host_id=internal.id, plugin_id="p1",
                               severity="critical", cvss_score=9.8, title="theoretical critical"),
        "epss": Finding(id=new_uuid(), scan_id=scan.id, host_id=internal.id, plugin_id="p2",
                        severity="high", cvss_score=7.5, title="likely exploited",
                        cve_ids=json.dumps(["CVE-2099-0001"])),
        "kev": Finding(id=new_uuid(), scan_id=scan.id, host_id=public.id, plugin_id="p3",
                       severity="medium", cvss_score=6.1, title="known exploited",
                       cve_ids=json.dumps(["CVE-2099-0002"])),
    }
    ids = {k: f.id for k, f in findings.items()}
    scan_id, admin_id = scan.id, admin.id
    db.add_all(findings.values())
    await db.commit()
    scored = await priority_service.rescore(db, Finding.scan_id == scan.id)
    assert scored == 3
    yield {"scan_id": scan_id, "ids": ids, "admin_id": admin_id}

    from scanr.api.v1.host_tags import HostTag
    await db.execute(sa_delete(HostTag).where(HostTag.ip == "10.20.30.40"))
    await db.execute(sa_delete(Finding).where(Finding.scan_id == scan_id))
    await db.execute(sa_delete(Host).where(Host.scan_id == scan_id))
    await db.execute(sa_delete(Scan).where(Scan.id == scan_id))
    await db.commit()


@pytest.mark.asyncio
async def test_priority_sort_and_fields(client, auth_headers, ranked):
    r = await client.get(f"/api/v1/findings?scan_id={ranked['scan_id']}&sort=priority", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert [f["title"] for f in body] == ["known exploited", "likely exploited", "theoretical critical"]
    top = body[0]
    assert top["is_kev"] is True and top["priority_score"] == pytest.approx(6.1 * 4 + 40 + 20 * (6.1 * 4 / 40) ** 0.5, abs=0.05)
    assert "internet-facing host" in json.loads(top["priority_reasons"])
    assert body[1]["epss_score"] == 0.64

    newest = await client.get(f"/api/v1/findings?scan_id={ranked['scan_id']}&min_priority=60", headers=auth_headers)
    assert {f["title"] for f in newest.json()} == {"known exploited", "likely exploited"}

    bad = await client.get("/api/v1/findings?sort=priority&cursor=2026-01-01T00:00:00,x", headers=auth_headers)
    assert bad.status_code == 400


@pytest.mark.asyncio
async def test_crown_jewel_tag_rescores_host(client, auth_headers, ranked, db):
    from scanr.models import Finding

    before = (await db.execute(select(Finding.priority_score).where(Finding.id == ranked["ids"]["theoretical"]))).scalar_one()
    r = await client.post("/api/v1/host-tags?ip=10.20.30.40&tag=Crown-Jewel", headers=auth_headers)
    assert r.status_code == 201
    db.expire_all()
    after = (await db.execute(select(Finding.priority_score).where(Finding.id == ranked["ids"]["theoretical"]))).scalar_one()
    assert after == pytest.approx(min(before + 20 * (9.8 * 4 / 40) ** 0.5, 100), abs=0.1)

    await client.delete("/api/v1/host-tags?ip=10.20.30.40&tag=crown-jewel", headers=auth_headers)
    db.expire_all()
    restored = (await db.execute(select(Finding.priority_score).where(Finding.id == ranked["ids"]["theoretical"]))).scalar_one()
    assert restored == pytest.approx(before)


@pytest.mark.asyncio
async def test_vulnerabilities_ranked_by_priority(client, auth_headers, ranked):
    r = await client.get("/api/v1/vulnerabilities?search=exploited", headers=auth_headers)
    items = {i["plugin_id"]: i for i in r.json()}
    assert items["p3"]["kev"] is True and items["p3"]["max_priority"] > items["p2"]["max_priority"]


@pytest.mark.asyncio
async def test_csv_export_includes_priority(client, auth_headers, ranked):
    r = await client.get(f"/api/v1/findings/export?scan_id={ranked['scan_id']}", headers=auth_headers)
    header = r.text.splitlines()[0].split(",")
    assert header[:2] == ["severity", "priority"] and "epss" in header and "cisa_kev" in header


@pytest.mark.asyncio
async def test_refresh_once_scores_unscored_findings(db, ranked, monkeypatch):
    from scanr.core import threat_feeds
    from scanr.models import Finding

    await db.execute(
        Finding.__table__.update().where(Finding.scan_id == ranked["scan_id"]).values(priority_score=None)
    )
    await db.commit()
    monkeypatch.setattr(threat_feeds, "refresh_feeds_if_stale", lambda: False)
    assert await threat_feeds.refresh_once() >= 3
    db.expire_all()
    missing = (await db.execute(
        select(Finding.id).where(Finding.scan_id == ranked["scan_id"], Finding.priority_score.is_(None))
    )).all()
    assert missing == []
