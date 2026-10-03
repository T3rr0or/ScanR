"""Audit trail: automatic coverage of mutating calls, sign-in events, access control."""
import uuid

import pytest
from sqlalchemy import select


async def _events(db, **filters):
    from scanr.models.audit_event import AuditEvent

    db.expire_all()
    q = select(AuditEvent).order_by(AuditEvent.created_at.desc())
    for key, value in filters.items():
        q = q.where(getattr(AuditEvent, key) == value)
    return (await db.execute(q)).scalars().all()


@pytest.mark.asyncio
async def test_mutating_calls_are_recorded_with_actor_and_target(client, auth_headers, db):
    r = await client.post("/api/v1/scans", json={"name": f"audit-{uuid.uuid4().hex[:6]}", "targets": ["198.51.100.20"]},
                          headers=auth_headers)
    assert r.status_code == 201, r.text
    scan_id = r.json()["id"]
    await client.patch(f"/api/v1/scans/{scan_id}", json={"description": "x"}, headers=auth_headers)
    await client.delete(f"/api/v1/scans/{scan_id}", headers=auth_headers)

    created = (await _events(db, action="scans.create"))[0]
    assert created.user_email == "admin@scanr.local" and created.auth_method == "session"
    assert created.status_code == 201 and created.method == "POST" and created.ip
    deleted = await _events(db, action="scans.delete", target_id=scan_id)
    assert deleted and deleted[0].target_type == "scans"
    assert await _events(db, action="scans.update", target_id=scan_id)


@pytest.mark.asyncio
async def test_secrets_in_request_bodies_are_never_stored(client, auth_headers, db):
    secret = f"S3cret-{uuid.uuid4().hex}"
    r = await client.post("/api/v1/credentials", json={"name": "audit-cred", "type": "ssh", "username": "root",
                                                       "secret_data": {"password": secret}}, headers=auth_headers)
    assert r.status_code in (200, 201), r.text
    from scanr.models.audit_event import AuditEvent

    rows = (await db.execute(select(AuditEvent))).scalars().all()
    assert all(secret not in (e.details or "") + (e.path or "") for e in rows)
    assert await _events(db, action="credentials.create")


@pytest.mark.asyncio
async def test_sign_in_events(client, db):
    email = "admin@scanr.local"
    await client.post("/api/v1/auth/login", json={"email": email, "password": "wrong-password"})
    await client.post("/api/v1/auth/login", json={"email": email, "password": "testadminpass123"})
    failed = await _events(db, action="auth.login_failed")
    assert failed and failed[0].user_email == email and failed[0].status_code == 401
    ok = await _events(db, action="auth.login")
    assert ok and ok[0].user_id and '"password"' in ok[0].details


@pytest.mark.asyncio
async def test_denied_calls_are_recorded_but_anonymous_noise_is_not(client, auth_headers, db):
    email = f"audit-viewer-{uuid.uuid4().hex[:6]}@scanr.local"
    await client.post("/api/v1/users", json={"email": email, "password": "long-enough-pw", "role": "viewer"},
                      headers=auth_headers)
    login = await client.post("/api/v1/auth/login", json={"email": email, "password": "long-enough-pw"})
    viewer = {"Authorization": f"Bearer {login.json()['access_token']}"}
    r = await client.post("/api/v1/scans", json={"name": "nope", "targets": ["198.51.100.21"]}, headers=viewer)
    assert r.status_code == 403
    denied = await _events(db, action="scans.create", user_email=email)
    assert denied and denied[0].status_code == 403

    before = len(await _events(db))
    await client.post("/api/v1/scans", json={"name": "anon", "targets": ["198.51.100.22"]})
    assert len(await _events(db)) == before


@pytest.mark.asyncio
async def test_api_key_calls_are_attributed(client, auth_headers, db):
    key = (await client.post("/api/v1/api-keys", json={"name": "audit", "scopes": ["scans:write", "scans:read"]},
                             headers=auth_headers)).json()["key"]
    r = await client.post("/api/v1/scans", json={"name": "via-key", "targets": ["198.51.100.23"]},
                          headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 201
    event = (await _events(db, action="scans.create", target_id=None, auth_method="api_key"))[0]
    assert event.user_email == "admin@scanr.local"


@pytest.mark.asyncio
async def test_audit_api_is_admin_only_filters_and_exports(client, auth_headers, db):
    r = await client.get("/api/v1/audit?action=auth.&limit=5", headers=auth_headers)
    assert r.status_code == 200 and r.json() and all(e["action"].startswith("auth.") for e in r.json())
    denied = await client.get("/api/v1/audit?outcome=denied", headers=auth_headers)
    assert all(e["status_code"] >= 400 for e in denied.json())

    export = await client.get("/api/v1/audit/export", headers=auth_headers)
    assert export.status_code == 200 and export.text.startswith("created_at,user_email")
    assert await _events(db, action="audit.export")

    email = f"audit-analyst-{uuid.uuid4().hex[:6]}@scanr.local"
    await client.post("/api/v1/users", json={"email": email, "password": "long-enough-pw"}, headers=auth_headers)
    login = await client.post("/api/v1/auth/login", json={"email": email, "password": "long-enough-pw"})
    analyst = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.get("/api/v1/audit", headers=analyst)).status_code == 403


@pytest.mark.asyncio
async def test_no_api_to_change_the_trail(client, auth_headers):
    for method in ("post", "delete", "patch", "put"):
        r = await getattr(client, method)("/api/v1/audit", headers=auth_headers)
        assert r.status_code == 405
