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
