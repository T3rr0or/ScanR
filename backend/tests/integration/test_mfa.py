"""Two-factor authentication: enrolment, login challenge, recovery and reset."""
from __future__ import annotations

import uuid

import pytest

from scanr.auth import totp

PASSWORD = "mfa-test-password-1"


@pytest.fixture
def clock(monkeypatch):
    """Drive TOTP time steps explicitly, so codes are never replays of each other."""
    state = {"step": totp.current_step() + 1000}
    monkeypatch.setattr(totp, "current_step", lambda now=None: state["step"])

    def code(secret: str) -> str:
        return totp._code_at(secret, state["step"])

    def advance() -> None:
        state["step"] += 1

    return code, advance


async def _new_user(client, auth_headers) -> tuple[str, str]:
    email = f"mfa-{uuid.uuid4().hex[:8]}@scanr.local"
    resp = await client.post(
        "/api/v1/users",
        json={"email": email, "password": PASSWORD, "role": "analyst"},
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    return email, resp.json()["id"]


async def _login(client, email: str, password: str = PASSWORD):
    return await client.post("/api/v1/auth/login", json={"email": email, "password": password})


async def _session(client, email: str) -> dict[str, str]:
    resp = await _login(client, email)
    assert resp.status_code == 200 and resp.json().get("access_token"), resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


async def _enrol(client, headers, clock) -> tuple[str, list[str]]:
    code, advance = clock
    setup = await client.post("/api/v1/users/me/mfa/setup", json={"password": PASSWORD}, headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/ScanR%3A")
    enable = await client.post("/api/v1/users/me/mfa/enable", json={"code": code(secret)}, headers=headers)
    assert enable.status_code == 200, enable.text
    advance()
    return secret, enable.json()["recovery_codes"]


@pytest.mark.asyncio
async def test_login_without_mfa_is_unchanged(client, auth_headers):
    email, _ = await _new_user(client, auth_headers)
    resp = await _login(client, email)
    assert resp.status_code == 200
    assert "mfa_required" not in resp.json() or resp.json()["mfa_required"] is False
    assert resp.json()["access_token"]


@pytest.mark.asyncio
async def test_setup_requires_password_and_is_not_enforced_until_confirmed(client, auth_headers, clock):
    email, _ = await _new_user(client, auth_headers)
    headers = await _session(client, email)
    bad = await client.post("/api/v1/users/me/mfa/setup", json={"password": "wrong"}, headers=headers)
    assert bad.status_code == 400
    ok = await client.post("/api/v1/users/me/mfa/setup", json={"password": PASSWORD}, headers=headers)
    assert ok.status_code == 200
    # Abandoned setup: login still works with just the password.
    assert (await _login(client, email)).json().get("access_token")
    wrong = await client.post("/api/v1/users/me/mfa/enable", json={"code": "000000"}, headers=headers)
    assert wrong.status_code == 400


@pytest.mark.asyncio
async def test_full_mfa_login_and_replay_protection(client, auth_headers, clock):
    code, advance = clock
    email, _ = await _new_user(client, auth_headers)
    headers = await _session(client, email)
    secret, recovery = await _enrol(client, headers, clock)
    assert len(recovery) == 10

    status = await client.get("/api/v1/users/me/mfa", headers=headers)
    assert status.json() == {"enabled": True, "recovery_codes_remaining": 10}

    first = await _login(client, email)
    assert first.status_code == 200
    body = first.json()
    assert body["mfa_required"] is True and "access_token" not in body
    assert "scanr_rt" not in first.cookies

    # The challenge token is not an access token.
    probe = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {body['mfa_token']}"})
    assert probe.status_code == 401

    bad = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": body["mfa_token"], "code": "123456"})
    assert bad.status_code == 401

    current = code(secret)
    good = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": body["mfa_token"], "code": current})
    assert good.status_code == 200, good.text
    assert good.json()["access_token"]
    assert "scanr_rt" in good.cookies

    # Same code again, on a fresh challenge: refused as a replay.
    second = (await _login(client, email)).json()["mfa_token"]
    replay = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": second, "code": current})
    assert replay.status_code == 401

    # A used challenge cannot mint a second session, even with a new code.
    advance()
    reuse = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": body["mfa_token"], "code": code(secret)})
    assert reuse.status_code == 401


@pytest.mark.asyncio
async def test_recovery_code_is_single_use(client, auth_headers, clock):
    email, _ = await _new_user(client, auth_headers)
    headers = await _session(client, email)
    _, recovery = await _enrol(client, headers, clock)

    token = (await _login(client, email)).json()["mfa_token"]
    used = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": token, "code": recovery[0].upper()})
    assert used.status_code == 200, used.text

    token = (await _login(client, email)).json()["mfa_token"]
    again = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": token, "code": recovery[0]})
    assert again.status_code == 401

    fresh = {"Authorization": f"Bearer {used.json()['access_token']}"}
    status = await client.get("/api/v1/users/me/mfa", headers=fresh)
    assert status.json()["recovery_codes_remaining"] == 9


@pytest.mark.asyncio
async def test_wrong_codes_count_towards_lockout(client, auth_headers, clock):
    code, _ = clock
    email, _ = await _new_user(client, auth_headers)
    headers = await _session(client, email)
    secret, _ = await _enrol(client, headers, clock)

    token = (await _login(client, email)).json()["mfa_token"]
    for _ in range(10):
        await client.post("/api/v1/auth/login/mfa", json={"mfa_token": token, "code": "000000"})
    locked = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": token, "code": code(secret)})
    assert locked.status_code == 429
    assert (await _login(client, email)).status_code == 429


@pytest.mark.asyncio
async def test_disable_requires_password_and_code(client, auth_headers, clock):
    code, _ = clock
    email, _ = await _new_user(client, auth_headers)
    headers = await _session(client, email)
    secret, _ = await _enrol(client, headers, clock)

    no_code = await client.post(
        "/api/v1/users/me/mfa/disable", json={"password": PASSWORD, "code": "000000"}, headers=headers
    )
    assert no_code.status_code == 400
    no_pw = await client.post(
        "/api/v1/users/me/mfa/disable", json={"password": "wrong-password", "code": code(secret)}, headers=headers
    )
    assert no_pw.status_code == 400
    ok = await client.post(
        "/api/v1/users/me/mfa/disable", json={"password": PASSWORD, "code": code(secret)}, headers=headers
    )
    assert ok.status_code == 204
    assert (await _login(client, email)).json().get("access_token")


@pytest.mark.asyncio
async def test_regenerate_recovery_codes(client, auth_headers, clock):
    code, _ = clock
    email, _ = await _new_user(client, auth_headers)
    headers = await _session(client, email)
    secret, old = await _enrol(client, headers, clock)
    resp = await client.post("/api/v1/users/me/mfa/recovery-codes", json={"code": code(secret)}, headers=headers)
    assert resp.status_code == 200
    new = resp.json()["recovery_codes"]
    assert set(new).isdisjoint(old)

    token = (await _login(client, email)).json()["mfa_token"]
    stale = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": token, "code": old[1]})
    assert stale.status_code == 401


@pytest.mark.asyncio
async def test_admin_reset_and_user_list_flag(client, auth_headers, clock):
    email, user_id = await _new_user(client, auth_headers)
    headers = await _session(client, email)
    await _enrol(client, headers, clock)

    listed = {u["id"]: u for u in (await client.get("/api/v1/users", headers=auth_headers)).json()}
    assert listed[user_id]["mfa_enabled"] is True

    forbidden = await client.post(f"/api/v1/users/{user_id}/mfa/reset", headers=headers)
    assert forbidden.status_code == 403
    reset = await client.post(f"/api/v1/users/{user_id}/mfa/reset", headers=auth_headers)
    assert reset.status_code == 200 and reset.json()["mfa_enabled"] is False
    assert (await _login(client, email)).json().get("access_token")


@pytest.mark.asyncio
async def test_password_change_invalidates_pending_challenge(client, auth_headers, clock):
    code, _ = clock
    email, _ = await _new_user(client, auth_headers)
    headers = await _session(client, email)
    secret, _ = await _enrol(client, headers, clock)
    token = (await _login(client, email)).json()["mfa_token"]

    changed = await client.post(
        "/api/v1/users/me/change-password",
        json={"current_password": PASSWORD, "new_password": "a-brand-new-password"},
        headers=headers,
    )
    assert changed.status_code == 204
    stale = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": token, "code": code(secret)})
    assert stale.status_code == 401
