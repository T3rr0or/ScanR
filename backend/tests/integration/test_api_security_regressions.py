"""Regression tests for security fixes: target-validation bypasses, refresh-token
revocation on password change, atomic launch, and 409 paths that previously
crashed on scan.status.value (str column, not enum)."""
import pytest


@pytest.mark.asyncio
async def test_patch_targets_denylist_rejected(client, auth_headers):
    r = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "patch-bypass", "targets": ["192.0.2.10"],
    })
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    r2 = await client.patch(f"/api/v1/scans/{sid}", headers=auth_headers, json={
        "targets": ["127.0.0.1"],
    })
    assert r2.status_code == 400, r2.text
    assert "not allowed" in r2.json()["detail"]


@pytest.mark.asyncio
async def test_patch_status_409_no_crash(client, auth_headers, db):
    """409 path must not AttributeError on scan.status.value."""
    from scanr.models import Scan, ScanStatus, Target
    from scanr.models.base import new_uuid
    from sqlalchemy import select
    from scanr.models.user import User

    uid = (await db.execute(select(User.id).where(User.email == "admin@scanr.local"))).scalars().one()
    scan = Scan(id=new_uuid(), name="running-scan", status=ScanStatus.running, user_id=uid)
    db.add(scan)
    db.add(Target(id=new_uuid(), scan_id=scan.id, value="192.0.2.10", type="ip"))
    await db.commit()
    r = await client.patch(f"/api/v1/scans/{scan.id}", headers=auth_headers, json={"name": "x"})
    assert r.status_code == 409, r.text
    assert "running" in r.json()["detail"]


@pytest.mark.asyncio
async def test_schedule_forbidden_target_rejected(client, auth_headers):
    r = await client.post("/api/v1/schedules", headers=auth_headers, json={
        "name": "evil", "targets": ["169.254.169.254"], "cron_expr": "0 3 * * *",
    })
    assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_schedule_foreign_credential_rejected(client, auth_headers, db):
    from scanr.models.credential import Credential
    from scanr.models.base import new_uuid
    from scanr.models.user import User, UserRole
    from scanr.auth.password import hash_password

    other = User(id=new_uuid(), email="other@x.com", hashed_password=hash_password("somepassword1"),
                 role=UserRole.analyst, is_active=True)
    db.add(other)
    await db.flush()
    cred = Credential(id=new_uuid(), user_id=other.id, name="other-cred", type="ssh",
                      username="u", encrypted_data=b"x")
    db.add(cred)
    await db.commit()

    r = await client.post("/api/v1/schedules", headers=auth_headers, json={
        "name": "foreign-cred", "targets": ["192.0.2.10"], "cron_expr": "0 3 * * *",
        "scan_profile_json": f'{{"credential_id": "{cred.id}"}}',
    })
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_password_change_revokes_refresh(client):
    login = await client.post("/api/v1/auth/login", json={
        "email": "admin@scanr.local", "password": "testadminpass123",
    })
    assert login.status_code == 200
    old_rt = login.cookies.get("scanr_rt")
    token = login.json()["access_token"]

    # change password (uses Authorization header; client cookie jar has old rt)
    r = await client.post("/api/v1/users/me/change-password",
                          headers={"Authorization": f"Bearer {token}"},
                          json={"current_password": "testadminpass123",
                                "new_password": "newadminpass123"})
    assert r.status_code == 204, r.text

    # old refresh token must now be rejected (predates pw epoch)
    r2 = await client.post("/api/v1/auth/refresh", cookies={"scanr_rt": old_rt})
    assert r2.status_code == 401, r2.text

    # fresh cookie issued by change-password keeps working
    new_rt = r.cookies.get("scanr_rt")
    assert new_rt and new_rt != old_rt
    r3 = await client.post("/api/v1/auth/refresh", cookies={"scanr_rt": new_rt})
    assert r3.status_code == 200, r3.text

    # restore admin password for other tests
    token2 = r3.json()["access_token"]
    r4 = await client.post("/api/v1/users/me/change-password",
                           headers={"Authorization": f"Bearer {token2}"},
                           json={"current_password": "newadminpass123",
                                 "new_password": "testadminpass123"})
    assert r4.status_code == 204, r4.text


@pytest.mark.asyncio
async def test_launch_conflict_message_no_crash(client, auth_headers, db):
    from scanr.models import Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User
    from sqlalchemy import select

    uid = (await db.execute(select(User.id).where(User.email == "admin@scanr.local"))).scalars().one()
    scan = Scan(id=new_uuid(), name="paused-scan", status=ScanStatus.paused, user_id=uid)
    db.add(scan)
    await db.commit()
    r = await client.post(f"/api/v1/scans/{scan.id}/launch", headers=auth_headers)
    assert r.status_code == 409, r.text
    assert "paused" in r.json()["detail"]


@pytest.mark.asyncio
async def test_import_oversize_rejected(client, auth_headers):
    r = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "import-cap", "targets": ["192.0.2.10"],
    })
    sid = r.json()["id"]
    big = "x" * (51 * 1024 * 1024)
    r2 = await client.post(f"/api/v1/scans/{sid}/import", headers=auth_headers,
                           json={"report": big})
    assert r2.status_code == 422, r2.status_code  # pydantic max_length
