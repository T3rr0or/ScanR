"""Regression tests: API-key scope enforcement (deps.require_scope) on routers
that previously accepted any authenticated API key, plus key-creation guards
(unknown scopes, self-escalation)."""
import uuid

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
@pytest.mark.parametrize(("path", "required_scope"), [
    ("/assets", "findings:read"),
    ("/analytics/severity-distribution", "findings:read"),
    ("/templates", "scans:read"),
    ("/scans/missing/exclusions", "scans:read"),
    ("/plugins/health", "plugins:read"),
    ("/system/stats", "scans:read"),
])
async def test_narrow_key_cannot_read_result_views(
    client, auth_headers, path, required_scope
):
    key = await _create_key(
        client, auth_headers, ["webhooks:read"], name=f"deny-{required_scope}-{path}"
    )
    response = await client.get(f"{PREFIX}{path}", headers={"X-API-Key": key})
    assert response.status_code == 403, response.text
    assert required_scope in response.json()["detail"]


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


@pytest.mark.asyncio
async def test_admin_owned_narrow_key_cannot_cross_privileged_boundaries(
    client, auth_headers
):
    """The account is an admin, but authority comes from role *and* key scope.

    This is the regression for the role-only require_admin dependency: before
    the fix, this findings-only key could create another administrator and alter
    global AI configuration.
    """
    key = await _create_key(
        client, auth_headers, ["findings:read"], name="admin-narrow-boundary"
    )
    h = {"X-API-Key": key}

    create_user = await client.post(
        f"{PREFIX}/users",
        headers=h,
        json={
            "email": "must-not-exist@scanr.local",
            "password": "notcreated123",
            "role": "admin",
        },
    )
    assert create_user.status_code == 403, create_user.text
    assert "users:manage" in create_user.json()["detail"]

    # The alternate Authorization: Bearer sk_... transport must preserve the
    # same principal type and scope restrictions as X-API-Key.
    bearer_create = await client.post(
        f"{PREFIX}/users",
        headers={"Authorization": f"Bearer {key}"},
        json={
            "email": "must-not-exist-bearer@scanr.local",
            "password": "notcreated123",
            "role": "admin",
        },
    )
    assert bearer_create.status_code == 403, bearer_create.text
    assert "users:manage" in bearer_create.json()["detail"]

    change_own_profile = await client.patch(
        f"{PREFIX}/users/me", headers=h, json={"full_name": "scope bypass"}
    )
    assert change_own_profile.status_code == 403, change_own_profile.text
    assert "Interactive user session" in change_own_profile.json()["detail"]

    set_ai_config = await client.put(
        f"{PREFIX}/ai/config", headers=h, json={"provider": "anthropic"}
    )
    assert set_ai_config.status_code == 403, set_ai_config.text
    assert "ai:configure" in set_ai_config.json()["detail"]

    set_integration = await client.put(
        f"{PREFIX}/integrations/topdesk",
        headers=h,
        json={
            "url": "https://example.topdesk.net",
            "username": "blocked",
            "password": "blocked",
        },
    )
    assert set_integration.status_code == 403, set_integration.text
    assert "integrations:manage" in set_integration.json()["detail"]


@pytest.mark.asyncio
async def test_explicit_admin_scopes_allow_only_the_intended_admin_automation(
    client, auth_headers
):
    key = await _create_key(
        client,
        auth_headers,
        ["users:manage", "ai:configure"],
        name="explicit-admin-automation",
    )
    h = {"X-API-Key": key}
    email = f"scoped-{uuid.uuid4().hex}@scanr.local"

    created = await client.post(
        f"{PREFIX}/users",
        headers=h,
        json={"email": email, "password": "scopedpass123", "role": "analyst"},
    )
    assert created.status_code == 201, created.text

    configured = await client.put(
        f"{PREFIX}/ai/config", headers=h, json={"provider": "anthropic"}
    )
    assert configured.status_code == 204, configured.text

    # It still cannot cross into another admin scope it was not granted.
    integration = await client.get(f"{PREFIX}/integrations/topdesk", headers=h)
    assert integration.status_code == 403, integration.text
    assert "integrations:manage" in integration.json()["detail"]

    deleted = await client.delete(
        f"{PREFIX}/users/{created.json()['id']}", headers=h
    )
    assert deleted.status_code == 204, deleted.text


@pytest.mark.asyncio
async def test_admin_scan_key_cannot_launch_or_embed_ai_agent(client, auth_headers):
    """scans:write does not implicitly grant LLM spend or autonomous tooling."""
    key = await _create_key(
        client, auth_headers, ["scans:write"], name="scan-without-ai-agent"
    )
    h = {"X-API-Key": key}

    launch = await client.post(
        f"{PREFIX}/ai/scans/{'0' * 36}/agent",
        headers=h,
        json={"mode": "guided"},
    )
    assert launch.status_code == 403, launch.text
    assert "ai:agent" in launch.json()["detail"]

    embedded = await client.post(
        f"{PREFIX}/scans",
        headers=h,
        json={
            "name": "scope-denied-auto-agent",
            "targets": ["192.0.2.201"],
            "ai_agent": {"enabled": True, "mode": "guided"},
        },
    )
    assert embedded.status_code == 403, embedded.text
    assert "ai:agent" in embedded.json()["detail"]


@pytest.mark.asyncio
async def test_ai_agent_scope_does_not_imply_aggressive_capabilities(
    client, auth_headers
):
    key = await _create_key(
        client,
        auth_headers,
        ["scans:write", "ai:agent"],
        name="agent-without-aggressive",
    )
    h = {"X-API-Key": key}
    scan = await client.post(
        f"{PREFIX}/scans",
        headers=h,
        json={"name": "aggressive-scope-boundary", "targets": ["192.0.2.202"]},
    )
    assert scan.status_code == 201, scan.text
    scan_id = scan.json()["id"]

    launch = await client.post(
        f"{PREFIX}/ai/scans/{scan_id}/agent",
        headers=h,
        json={"mode": "autonomous", "aggressive": True, "allow_command_exec": True},
    )
    assert launch.status_code == 403, launch.text
    assert "ai:aggressive" in launch.json()["detail"]

    deleted = await client.delete(f"{PREFIX}/scans/{scan_id}", headers=h)
    assert deleted.status_code == 204, deleted.text


@pytest.mark.asyncio
async def test_full_api_key_still_cannot_trigger_session_only_self_update(
    client, auth_headers
):
    key = await _create_key(client, auth_headers, ["*"], name="full-but-not-session")
    response = await client.post(
        f"{PREFIX}/system/update", headers={"X-API-Key": key}
    )
    assert response.status_code == 403, response.text
    assert "Interactive admin session" in response.json()["detail"]


@pytest.mark.asyncio
async def test_ai_generation_requires_findings_read_as_well_as_ai_scope(
    client, auth_headers
):
    only_ai = await _create_key(
        client, auth_headers, ["ai:generate"], name="ai-without-findings"
    )
    response = await client.post(
        f"{PREFIX}/ai/scans/{'0' * 36}/summary",
        headers={"X-API-Key": only_ai},
        json={},
    )
    assert response.status_code == 403, response.text
    assert "findings:read" in response.json()["detail"]

    only_findings = await _create_key(
        client, auth_headers, ["findings:read"], name="findings-without-ai"
    )
    response = await client.post(
        f"{PREFIX}/ai/scans/{'0' * 36}/summary",
        headers={"X-API-Key": only_findings},
        json={},
    )
    assert response.status_code == 403, response.text
    assert "ai:generate" in response.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("target", [
    "2130706433",      # decimal 127.0.0.1
    "0x7f000001",      # hex 127.0.0.1
    "017700000001",    # octal 127.0.0.1
    "127.1",           # short-form 127.0.0.1
    "2852039166",      # decimal 169.254.169.254 (cloud metadata)
])
async def test_legacy_numeric_loopback_encodings_rejected_at_creation(client, auth_headers, target):
    """These used to be accepted as 'hostnames' and only caught later by the
    engine's resolve-time backstop, which failed the scan instead of the request."""
    r = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": f"legacy-{target}", "targets": [target],
    })
    assert r.status_code == 400, r.text
