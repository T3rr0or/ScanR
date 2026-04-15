import pytest


@pytest.mark.asyncio
async def test_create_scan(client, auth_headers):
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Test Scan",
        "targets": ["127.0.0.1"],
        "profile": "quick",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test Scan"
    assert data["status"] == "pending"
    assert data["profile"] == "quick"
    return data["id"]


@pytest.mark.asyncio
async def test_create_scan_no_targets(client, auth_headers):
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Empty",
        "targets": [],
        "profile": "quick",
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_list_scans(client, auth_headers):
    resp = await client.get("/api/v1/scans", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_get_scan_not_found(client, auth_headers):
    resp = await client.get("/api/v1/scans/nonexistent-id", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_and_delete_scan(client, auth_headers):
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Delete Me",
        "targets": ["10.0.0.1"],
        "profile": "quick",
    })
    scan_id = resp.json()["id"]

    del_resp = await client.delete(f"/api/v1/scans/{scan_id}", headers=auth_headers)
    assert del_resp.status_code == 204

    get_resp = await client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_plugins_list(client, auth_headers):
    resp = await client.get("/api/v1/plugins", headers=auth_headers)
    assert resp.status_code == 200
    plugins = resp.json()
    assert len(plugins) > 10
    ids = [p["id"] for p in plugins]
    assert "ssl_tls.heartbleed" in ids
    assert "services.smb_vulns" in ids


@pytest.mark.asyncio
async def test_system_health(client):
    resp = await client.get("/api/v1/system/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
