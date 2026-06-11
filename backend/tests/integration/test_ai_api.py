import pytest


@pytest.mark.asyncio
async def test_ai_key_roundtrip_and_never_returned(client, auth_headers):
    # Set an encrypted key from the web app
    r = await client.put(
        "/api/v1/ai/keys/anthropic",
        headers=auth_headers,
        json={"api_key": "sk-ant-secret-value-123"},
    )
    assert r.status_code == 204

    # Status reflects it, sourced from storage — and the key is never echoed back
    s = await client.get("/api/v1/ai/status", headers=auth_headers)
    assert s.status_code == 200
    data = s.json()
    assert data["configured"]["anthropic"] is True
    assert data["key_sources"]["anthropic"] == "stored"
    assert data["enabled"] is True
    assert "sk-ant-secret-value-123" not in s.text

    # Clear it again (cleanup — DB is shared across tests)
    d = await client.delete("/api/v1/ai/keys/anthropic", headers=auth_headers)
    assert d.status_code == 204
    s2 = await client.get("/api/v1/ai/status", headers=auth_headers)
    assert s2.json()["configured"]["anthropic"] is False


@pytest.mark.asyncio
async def test_ai_key_invalid_provider(client, auth_headers):
    r = await client.put(
        "/api/v1/ai/keys/bogus", headers=auth_headers, json={"api_key": "whatever123"}
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_ai_key_requires_auth(client):
    r = await client.put("/api/v1/ai/keys/anthropic", json={"api_key": "whatever123"})
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_ai_config_default_provider(client, auth_headers):
    r = await client.put("/api/v1/ai/config", headers=auth_headers, json={"provider": "deepseek"})
    assert r.status_code == 204
    s = await client.get("/api/v1/ai/status", headers=auth_headers)
    assert s.json()["default_provider"] == "deepseek"
    # restore default
    await client.put("/api/v1/ai/config", headers=auth_headers, json={"provider": "anthropic"})


@pytest.mark.asyncio
async def test_ai_model_override_and_clear(client, auth_headers):
    # Default (no override) — effective model is the provider's built-in default
    s0 = (await client.get("/api/v1/ai/status", headers=auth_headers)).json()
    assert s0["model_overrides"]["anthropic"] is None
    assert s0["effective_models"]["anthropic"] == s0["default_models"]["anthropic"]

    # Set an override
    r = await client.put(
        "/api/v1/ai/models/anthropic", headers=auth_headers, json={"model": "claude-sonnet-4-6"}
    )
    assert r.status_code == 204
    s1 = (await client.get("/api/v1/ai/status", headers=auth_headers)).json()
    assert s1["model_overrides"]["anthropic"] == "claude-sonnet-4-6"
    assert s1["effective_models"]["anthropic"] == "claude-sonnet-4-6"

    # Clear it (empty string) — reverts to default
    r2 = await client.put("/api/v1/ai/models/anthropic", headers=auth_headers, json={"model": ""})
    assert r2.status_code == 204
    s2 = (await client.get("/api/v1/ai/status", headers=auth_headers)).json()
    assert s2["model_overrides"]["anthropic"] is None


@pytest.mark.asyncio
async def test_ai_model_invalid_provider(client, auth_headers):
    r = await client.put("/api/v1/ai/models/bogus", headers=auth_headers, json={"model": "x"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_ai_summary_without_key_returns_400(client, auth_headers):
    scan = await client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={"name": "AI summary test", "targets": ["192.0.2.10"], "profile": "quick"},
    )
    assert scan.status_code == 201
    scan_id = scan.json()["id"]

    # openai has no key configured (stored or env) -> 400 before any network call
    r = await client.post(
        f"/api/v1/ai/scans/{scan_id}/summary",
        headers=auth_headers,
        json={"provider": "openai"},
    )
    assert r.status_code == 400
    assert "api key" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_agent_launch_without_key_returns_400(client, auth_headers):
    scan = await client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={"name": "agent test", "targets": ["192.0.2.20"], "profile": "quick"},
    )
    scan_id = scan.json()["id"]
    r = await client.post(
        f"/api/v1/ai/scans/{scan_id}/agent",
        headers=auth_headers,
        json={"mode": "guided", "provider": "openai"},
    )
    assert r.status_code == 400
    assert "api key" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_agent_runs_list_empty_and_run_not_found(client, auth_headers):
    scan = await client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={"name": "agent test 2", "targets": ["192.0.2.21"], "profile": "quick"},
    )
    scan_id = scan.json()["id"]
    runs = await client.get(f"/api/v1/ai/scans/{scan_id}/agent/runs", headers=auth_headers)
    assert runs.status_code == 200 and runs.json() == []

    nf = await client.get("/api/v1/ai/agent/runs/does-not-exist", headers=auth_headers)
    assert nf.status_code == 404


@pytest.mark.asyncio
async def test_agent_launch_invalid_mode_rejected(client, auth_headers):
    scan = await client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={"name": "agent test 3", "targets": ["192.0.2.22"], "profile": "quick"},
    )
    scan_id = scan.json()["id"]
    r = await client.post(
        f"/api/v1/ai/scans/{scan_id}/agent",
        headers=auth_headers,
        json={"mode": "rampage"},
    )
    assert r.status_code == 422  # pydantic pattern rejects unknown mode
