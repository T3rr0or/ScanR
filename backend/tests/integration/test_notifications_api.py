"""Notification channels API and the scan-finished trigger."""
import json

import pytest
from sqlalchemy import delete as sa_delete, select

SLACK = "https://hooks.slack.com/services/T000/B000/secretpart"


@pytest.fixture
def captured(monkeypatch):
    from scanr.core import notifications

    calls = []

    async def fake_post(url, payload):
        calls.append((url, payload))

    monkeypatch.setattr(notifications, "_post_json", fake_post)
    return calls


async def _create(client, headers, **body):
    payload = {"name": "SOC", "kind": "slack", "target": SLACK, **body}
    return await client.post("/api/v1/notifications", json=payload, headers=headers)


@pytest.mark.asyncio
async def test_crud_hides_webhook_url_and_encrypts_it(client, auth_headers, db):
    from scanr.models.notification_channel import NotificationChannel

    r = await _create(client, auth_headers, min_priority=60)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["target"] == "hooks.slack.com/…" and "secretpart" not in r.text
    assert body["events"] == ["scan.completed", "scan.failed"] and body["min_priority"] == 60
    stored = (await db.execute(select(NotificationChannel.target).where(NotificationChannel.id == body["id"]))).scalar_one()
    assert "secretpart" not in stored

    upd = await client.patch(f"/api/v1/notifications/{body['id']}",
                             json={"clear_min_priority": True, "events": ["scan.failed"], "enabled": False},
                             headers=auth_headers)
    assert upd.json()["min_priority"] is None and upd.json()["events"] == ["scan.failed"] and not upd.json()["enabled"]

    listed = await client.get("/api/v1/notifications", headers=auth_headers)
    assert any(c["id"] == body["id"] for c in listed.json())
    assert (await client.delete(f"/api/v1/notifications/{body['id']}", headers=auth_headers)).status_code == 204


@pytest.mark.asyncio
async def test_rejects_foreign_hosts_and_unconfigured_email(client, auth_headers):
    bad = await _create(client, auth_headers, target="https://attacker.example/hook")
    assert bad.status_code == 422 and "hooks.slack.com" in bad.json()["detail"]
    email = await _create(client, auth_headers, kind="email", target="soc@example.com")
    assert email.status_code == 400 and "SMTP_HOST" in email.json()["detail"]
    cfg = await client.get("/api/v1/notifications/config", headers=auth_headers)
    assert cfg.json() == {"email_enabled": False}


@pytest.mark.asyncio
async def test_test_endpoint_records_outcome(client, auth_headers, captured, monkeypatch):
    channel = (await _create(client, auth_headers, kind="teams",
                             target="https://contoso.webhook.office.com/webhookb2/x")).json()
    ok = await client.post(f"/api/v1/notifications/{channel['id']}/test", headers=auth_headers)
    assert ok.json()["last_status"] == "sent" and captured[-1][0].startswith("https://contoso.webhook.office.com/")
    assert captured[-1][1]["attachments"][0]["content"]["type"] == "AdaptiveCard"

    from scanr.core import notifications

    async def failing(url, payload):
        raise notifications.NotificationError("HTTP 404: no such webhook")

    monkeypatch.setattr(notifications, "_post_json", failing)
    bad = await client.post(f"/api/v1/notifications/{channel['id']}/test", headers=auth_headers)
    assert bad.json()["last_status"] == "failed" and "404" in bad.json()["last_error"]
    await client.delete(f"/api/v1/notifications/{channel['id']}", headers=auth_headers)


@pytest.mark.asyncio
async def test_other_users_cannot_see_or_use_channels(client, auth_headers):
    channel = (await _create(client, auth_headers)).json()
    await client.post("/api/v1/users", json={"email": "notif-other@scanr.local", "password": "long-enough-pw"},
                      headers=auth_headers)
    login = await client.post("/api/v1/auth/login", json={"email": "notif-other@scanr.local", "password": "long-enough-pw"})
    other = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.get("/api/v1/notifications", headers=other)).json() == []
    assert (await client.post(f"/api/v1/notifications/{channel['id']}/test", headers=other)).status_code == 404
    assert (await client.delete(f"/api/v1/notifications/{channel['id']}", headers=other)).status_code == 404
    await client.delete(f"/api/v1/notifications/{channel['id']}", headers=auth_headers)


@pytest.mark.asyncio
async def test_scan_finished_sends_summary_respecting_threshold(client, auth_headers, db, captured):
    from scanr.core.notifications import notify_scan_finished
    from scanr.models import Finding, Host, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    loud = (await _create(client, auth_headers, name="all")).json()
    quiet = (await _create(client, auth_headers, name="only urgent", min_priority=90)).json()
    failures = (await _create(client, auth_headers, name="failures", events=["scan.failed"])).json()

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    scan_id, host_id = new_uuid(), new_uuid()
    db.add(Scan(id=scan_id, name="Weekly external", status=ScanStatus.completed, profile="standard",
                user_id=admin.id, hosts_up=3, findings_high=1))
    await db.flush()
    db.add(Host(id=host_id, scan_id=scan_id, ip="93.184.216.34", status="up"))
    await db.flush()
    db.add(Finding(id=new_uuid(), scan_id=scan_id, host_id=host_id, plugin_id="p", severity="high",
                   title="Exposed admin panel", port_number=8443, priority_score=72.0,
                   priority_reasons=json.dumps(["high severity", "no exploitation data", "internet-facing host"])))
    await db.commit()

    assert await notify_scan_finished(db, scan_id) == 1
    assert len(captured) == 1
    text = captured[0][1]["blocks"][0]["text"]["text"]
    assert "Scan finished: Weekly external" in text and "[72] Exposed admin panel (93.184.216.34:8443)" in text

    for cid in (loud["id"], quiet["id"], failures["id"]):
        await client.delete(f"/api/v1/notifications/{cid}", headers=auth_headers)
    await db.execute(sa_delete(Finding).where(Finding.scan_id == scan_id))
    await db.execute(sa_delete(Host).where(Host.scan_id == scan_id))
    await db.execute(sa_delete(Scan).where(Scan.id == scan_id))
    await db.commit()


@pytest.mark.asyncio
async def test_deleting_user_removes_their_channels(client, auth_headers):
    await client.post("/api/v1/users", json={"email": "notif-del@scanr.local", "password": "long-enough-pw"},
                      headers=auth_headers)
    login = await client.post("/api/v1/auth/login", json={"email": "notif-del@scanr.local", "password": "long-enough-pw"})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await _create(client, headers)).status_code == 201
    users = (await client.get("/api/v1/users", headers=auth_headers)).json()
    uid = next(u["id"] for u in users if u["email"] == "notif-del@scanr.local")
    assert (await client.delete(f"/api/v1/users/{uid}", headers=auth_headers)).status_code == 204
