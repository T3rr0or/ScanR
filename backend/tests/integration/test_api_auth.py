import pytest


@pytest.mark.asyncio
async def test_login_success(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "testadminpass123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    # refresh_token is now delivered as an HttpOnly cookie, not in the body
    assert data.get("refresh_token") is None
    assert "scanr_rt" in resp.cookies


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "wrongpassword"},
    )
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


@pytest.mark.asyncio
async def test_refresh_via_cookie(client):
    """Refresh token in HttpOnly cookie is used to get a new access token."""
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "testadminpass123"},
    )
    assert login.status_code == 200
    # httpx stores cookies; the next request sends them automatically
    refresh = await client.post("/api/v1/auth/refresh")
    assert refresh.status_code == 200
    assert "access_token" in refresh.json()


@pytest.mark.asyncio
async def test_refresh_token_rotates(client):
    """Used refresh token is revoked — reuse must return 401."""
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "testadminpass123"},
    )
    rt = login.cookies.get("scanr_rt")
    assert rt

    # First refresh succeeds
    r1 = await client.post("/api/v1/auth/refresh", cookies={"scanr_rt": rt})
    assert r1.status_code == 200

    # Reuse of old token must fail (revoked)
    r2 = await client.post("/api/v1/auth/refresh", cookies={"scanr_rt": rt})
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_type_rejected_as_access(client):
    """Refresh token must not work as an access token for API calls."""
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "testadminpass123"},
    )
    rt = login.cookies.get("scanr_rt")
    resp = await client.get("/api/v1/scans", headers={"Authorization": f"Bearer {rt}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_cookie(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "testadminpass123"},
    )
    assert login.status_code == 200

    logout = await client.post("/api/v1/auth/logout")
    assert logout.status_code == 204

    # After logout the cookie is cleared — refresh should fail
    refresh = await client.post("/api/v1/auth/refresh")
    assert refresh.status_code == 401


@pytest.mark.asyncio
async def test_get_own_profile(client, auth_headers):
    resp = await client.get("/api/v1/users/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "admin@scanr.local"
    assert data["role"] == "admin"


@pytest.mark.asyncio
async def test_change_password_wrong_current(client, auth_headers):
    resp = await client.post(
        "/api/v1/users/me/change-password",
        json={"current_password": "wrongpass", "new_password": "newpassword123"},
        headers=auth_headers,
    )
    assert resp.status_code == 400
