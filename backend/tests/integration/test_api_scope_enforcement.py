"""Regression tests: API-key scope enforcement (deps.require_scope) on routers
that previously accepted any authenticated API key, plus key-creation guards
(unknown scopes, self-escalation)."""
import pytest

PREFIX = "/api/v1"


async def _create_key(client, auth_headers, scopes, name="t"):
    r = await client.post(
        f"{PREFIX}/api-keys", headers=auth_headers, json={"name": name, "scopes": scopes}
    )
    assert r.status_code == 201, r.text
    return r.json()["key"]


@pytest.mark.asyncio
async def test_unknown_scope_rejected_at_creation(client, auth_headers):
    r = await client.post(
        f"{PREFIX}/api-keys",
        headers=auth_headers,
        json={"name": "bad", "scopes": ["bogus:read"]},
    )
    assert r.status_code == 400, r.text
    assert "Unknown scopes" in r.json()["detail"]


@pytest.mark.asyncio
async def test_limited_key_forbidden_on_other_routers(client, auth_headers):
    """A findings:read key must not reach credentials/webhooks/api-keys."""
    key = await _create_key(client, auth_headers, ["findings:read"])
    h = {"X-API-Key": key}

    r = await client.get(f"{PREFIX}/credentials", headers=h)
    assert r.status_code == 403, r.text
    assert "credentials:read" in r.json()["detail"]

    r = await client.delete(f"{PREFIX}/credentials/{'0' * 36}", headers=h)
    assert r.status_code == 403, r.text

    r = await client.post(
        f"{PREFIX}/webhooks",
        headers=h,
        json={"name": "w", "url": "https://example.com/hook"},
    )
    assert r.status_code == 403, r.text

    r = await client.post(
        f"{PREFIX}/api-keys", headers=h, json={"name": "sub", "scopes": ["findings:read"]}
    )
    assert r.status_code == 403, r.text

    # Positive control: the one scope it does have must work.
    r = await client.get(f"{PREFIX}/findings", headers=h)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_key_cannot_mint_beyond_own_scopes(client, auth_headers):
    """Self-escalation guard: an api_keys:write key can mint within its own
    scope set only — otherwise it could create a '*' key and take over."""
    key = await _create_key(client, auth_headers, ["api_keys:write"])
    h = {"X-API-Key": key}

    r = await client.post(
        f"{PREFIX}/api-keys", headers=h, json={"name": "esc", "scopes": ["scans:write"]}
    )
    assert r.status_code == 403, r.text

    # Minting within its own scope set is allowed.
    r = await client.post(
        f"{PREFIX}/api-keys", headers=h, json={"name": "ok", "scopes": ["api_keys:write"]}
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_session_auth_retains_full_scopes(client, auth_headers):
    """Browser (JWT) sessions hold '*' — scope checks must not break the UI."""
    r = await client.get(f"{PREFIX}/credentials", headers=auth_headers)
    assert r.status_code == 200, r.text
    r = await client.get(f"{PREFIX}/api-keys", headers=auth_headers)
    assert r.status_code == 200, r.text
