"""The 'viewer' role must actually be read-only.

UserRole has defined admin/analyst/viewer since the beginning, but authorization
only ever compared role against "admin", so a viewer had the same write access as
an analyst: launch scans, triage findings, upload wordlists, create schedules.
"""
import json

import pytest


@pytest.fixture
async def viewer_headers(client, auth_headers):
    """Create a viewer user, yield its auth headers, then clean it up."""
    created = await client.post(
        "/api/v1/users",
        json={"email": "viewer-role@scanr.local", "password": "viewerpass123", "role": "viewer"},
        headers=auth_headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["role"] == "viewer", "role must round-trip as a plain string"
    uid = created.json()["id"]

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "viewer-role@scanr.local", "password": "viewerpass123"},
    )
    assert login.status_code == 200, login.text
    yield {"Authorization": f"Bearer {login.json()['access_token']}"}

    await client.delete(f"/api/v1/users/{uid}", headers=auth_headers)


@pytest.mark.asyncio
async def test_viewer_cannot_create_scan(client, viewer_headers):
    r = await client.post("/api/v1/scans", headers=viewer_headers, json={
        "name": "viewer-scan", "targets": ["192.0.2.10"],
    })
    assert r.status_code == 403, r.text
    assert "read-only" in r.json()["detail"]


@pytest.mark.asyncio
async def test_viewer_cannot_create_schedule(client, viewer_headers):
    r = await client.post("/api/v1/schedules", headers=viewer_headers, json={
        "name": "viewer-sched",
        "targets": ["192.0.2.10"],
        "cron_expr": "0 3 * * *",
        "scan_profile_json": json.dumps({"port_range": "top-1000"}),
    })
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_viewer_cannot_create_template(client, viewer_headers):
    r = await client.post("/api/v1/templates", headers=viewer_headers, json={
        "name": "viewer-tpl", "profile_json": {"port_range": "top-1000"},
    })
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_viewer_cannot_create_api_key(client, viewer_headers):
    r = await client.post("/api/v1/api-keys", headers=viewer_headers, json={"name": "viewer-key"})
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_viewer_cannot_create_webhook(client, viewer_headers):
    r = await client.post("/api/v1/webhooks", headers=viewer_headers, json={
        "name": "viewer-hook", "url": "https://example.com/hook",
    })
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_viewer_can_still_read(client, viewer_headers):
    """Read-only must mean read-*able* — the role is useless otherwise."""
    for path in ("/api/v1/scans", "/api/v1/templates", "/api/v1/schedules",
                 "/api/v1/findings", "/api/v1/wordlists", "/api/v1/reports"):
        r = await client.get(path, headers=viewer_headers)
        assert r.status_code == 200, f"{path} -> {r.status_code} {r.text}"


@pytest.mark.asyncio
async def test_viewer_can_change_own_password(client, viewer_headers):
    """Self-service account management is not a 'write' in the role sense."""
    r = await client.post("/api/v1/users/me/change-password", headers=viewer_headers, json={
        "current_password": "viewerpass123", "new_password": "viewerpass456",
    })
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
async def test_analyst_can_still_write(client, auth_headers):
    """The viewer gate must not catch analysts."""
    created = await client.post(
        "/api/v1/users",
        json={"email": "analyst-role@scanr.local", "password": "analystpass123", "role": "analyst"},
        headers=auth_headers,
    )
    assert created.status_code == 201, created.text
    uid = created.json()["id"]
    login = await client.post("/api/v1/auth/login", json={
        "email": "analyst-role@scanr.local", "password": "analystpass123",
    })
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    r = await client.post("/api/v1/scans", headers=headers, json={
        "name": "analyst-scan", "targets": ["192.0.2.11"],
    })
    assert r.status_code == 201, r.text

    await client.delete(f"/api/v1/users/{uid}", headers=auth_headers)


@pytest.mark.asyncio
async def test_invalid_role_rejected(client, auth_headers):
    """A typo'd role must 422, not silently create an un-privileged user."""
    r = await client.post(
        "/api/v1/users",
        json={"email": "bad-role@scanr.local", "password": "badrolepass123", "role": "Admin"},
        headers=auth_headers,
    )
    assert r.status_code == 422, r.text
