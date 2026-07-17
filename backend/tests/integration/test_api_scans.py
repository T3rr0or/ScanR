import pytest


@pytest.mark.asyncio
async def test_create_scan(client, auth_headers):
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Test Scan",
        "targets": ["192.0.2.10"],
        "profile": "quick",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test Scan"
    assert data["status"] == "pending"
    assert data["profile"] == "quick"


@pytest.mark.asyncio
async def test_create_scan_no_targets(client, auth_headers):
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Empty",
        "targets": [],
        "profile": "quick",
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_scan_invalid_target_rejected_at_api(client, auth_headers):
    """Invalid targets are now caught at create time (not silently at scan run time)."""
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Bad Target",
        "targets": ["192.168.1.1/8"],  # /8 exceeds max /16
        "profile": "quick",
    })
    assert resp.status_code == 400
    assert "too large" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_create_scan_invalid_hostname_rejected(client, auth_headers):
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Injection Attempt",
        "targets": ["; rm -rf /"],
        "profile": "quick",
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_scan_profile_json_masscan_rate_capped(client, auth_headers):
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Too Fast",
        "targets": ["192.0.2.10"],
        "profile": "custom",
        "profile_json": '{"masscan_rate": 9999999}',
    })
    assert resp.status_code == 400
    assert "masscan_rate" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_create_scan_profile_json_port_range_capped(client, auth_headers):
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Too Many Ports",
        "targets": ["192.0.2.10"],
        "profile": "custom",
        "profile_json": '{"port_range": "top-99999"}',
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_scan_rejects_loopback_target(client, auth_headers):
    """Scope guardrail: loopback targets (scanner host) are rejected."""
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Self scan",
        "targets": ["127.0.0.1"],
        "profile": "quick",
    })
    assert resp.status_code == 400
    assert "not allowed" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_create_scan_rejects_metadata_target(client, auth_headers):
    """Scope guardrail: cloud metadata link-local address is rejected."""
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Metadata grab",
        "targets": ["169.254.169.254"],
        "profile": "quick",
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_scan_rejects_infra_hostname(client, auth_headers):
    """Scope guardrail: infrastructure hostnames from the denylist are rejected."""
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "DB scan",
        "targets": ["postgres"],
        "profile": "quick",
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_scan_rejects_unowned_credential(client, auth_headers):
    """A scan cannot reference a vault credential the user does not own."""
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Borrowed cred",
        "targets": ["192.0.2.10"],
        "profile": "quick",
        "credential_id": "00000000-0000-0000-0000-000000000000",
    })
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_scans(client, auth_headers):
    resp = await client.get("/api/v1/scans", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_list_scans_pagination(client, auth_headers):
    resp = await client.get("/api/v1/scans?limit=5&offset=0", headers=auth_headers)
    assert resp.status_code == 200


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
    assert resp.status_code == 201
    scan_id = resp.json()["id"]

    del_resp = await client.delete(f"/api/v1/scans/{scan_id}", headers=auth_headers)
    assert del_resp.status_code == 204

    get_resp = await client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_scan_ownership_isolation(client, auth_headers):
    """Users can only see their own scans."""
    # Create a scan
    resp = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "Mine",
        "targets": ["10.0.0.1"],
        "profile": "quick",
    })
    scan_id = resp.json()["id"]

    # Accessing with same user: OK
    assert (await client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)).status_code == 200

    # Accessing without auth: 401
    assert (await client.get(f"/api/v1/scans/{scan_id}")).status_code in (401, 403)


@pytest.mark.asyncio
async def test_plugins_list(client, auth_headers):
    resp = await client.get("/api/v1/plugins", headers=auth_headers)
    assert resp.status_code == 200
    plugins = resp.json()
    assert len(plugins) > 10
    ids = [p["id"] for p in plugins]
    assert "ssl_tls.heartbleed" in ids
    assert "services.smb_vulns" in ids
    assert "services.ms17_010_check" in ids  # new plugins present
    assert "web.log4shell_check" in ids


@pytest.mark.asyncio
async def test_system_health(client):
    resp = await client.get("/api/v1/system/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_system_stats(client, auth_headers):
    resp = await client.get("/api/v1/system/stats", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "scans_total" in data
    assert "findings_total" in data


@pytest.mark.asyncio
async def test_credentials_uniqueness(client, auth_headers):
    """Duplicate credential name returns 409."""
    body = {"name": "unique-cred", "type": "ssh", "secret_data": {"password": "x"}}
    r1 = await client.post("/api/v1/credentials", headers=auth_headers, json=body)
    assert r1.status_code == 201

    r2 = await client.post("/api/v1/credentials", headers=auth_headers, json=body)
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_findings_cursor_pagination(client, auth_headers):
    """Findings endpoint accepts cursor param without error."""
    resp = await client.get("/api/v1/findings?limit=10", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_findings_mitre_invalid_rejected(client, auth_headers):
    resp = await client.get("/api/v1/findings?mitre_technique=INVALID", headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_findings_mitre_valid(client, auth_headers):
    resp = await client.get("/api/v1/findings?mitre_technique=T1110", headers=auth_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_users_me(client, auth_headers):
    resp = await client.get("/api/v1/users/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "admin@scanr.local"
    assert data["role"] == "admin"


@pytest.mark.asyncio
async def test_users_admin_list(client, auth_headers):
    resp = await client.get("/api/v1/users", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
    assert len(resp.json()) >= 1


@pytest.mark.asyncio
async def test_schedule_sub_hourly_rejected(client, auth_headers):
    resp = await client.post("/api/v1/schedules", headers=auth_headers, json={
        "name": "Too Frequent",
        "targets": ["192.0.2.10"],  # valid target — schedules now denylist-check targets
        "cron_expr": "* * * * *",  # every minute
    })
    assert resp.status_code == 400
    assert "interval" in resp.json()["detail"].lower()
