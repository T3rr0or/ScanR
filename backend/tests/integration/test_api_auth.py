import pytest


@pytest.mark.asyncio
async def test_login_success(client):
    resp = await client.post("/api/v1/auth/login", json={"email": "admin@scanr.local", "password": "changeme"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    resp = await client.post("/api/v1/auth/login", json={"email": "admin@scanr.local", "password": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(client):
    resp = await client.post("/api/v1/auth/login", json={"email": "nobody@x.com", "password": "x"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_no_token(client):
    resp = await client.get("/api/v1/scans")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_protected_endpoint_with_token(client, auth_headers):
    resp = await client.get("/api/v1/scans", headers=auth_headers)
    assert resp.status_code == 200
