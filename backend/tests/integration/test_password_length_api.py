"""Over-long passwords must be rejected as client errors, and a failed password
change must never revoke the caller's sessions.

Regression: both password fields declared min_length but no upper bound, so a
passphrase over bcrypt's 72-byte ceiling reached the hasher and raised —
returning 500. On /me/change-password the refresh-token epoch was bumped
*before* hashing, so the failure also logged the user out of every device while
leaving the old password valid.
"""
import pytest

# Over 72 bytes, but comfortably over min_length=10 so it reaches the byte check.
LONG_PASSWORD = "A" * 80
# 24 characters, 96 bytes — passes any character-counted length check.
MULTIBYTE_PASSWORD = "🔒" * 24


@pytest.mark.asyncio
@pytest.mark.parametrize("password", [LONG_PASSWORD, MULTIBYTE_PASSWORD])
async def test_change_password_rejects_over_long(client, auth_headers, password):
    r = await client.post(
        "/api/v1/users/me/change-password",
        headers=auth_headers,
        json={"current_password": "testadminpass123", "new_password": password},
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("password", [LONG_PASSWORD, MULTIBYTE_PASSWORD])
async def test_admin_create_user_rejects_over_long(client, auth_headers, password):
    r = await client.post(
        "/api/v1/users",
        headers=auth_headers,
        json={"email": "longpw@example.com", "password": password, "role": "analyst"},
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_boundary_password_is_accepted(client, auth_headers):
    """72 bytes is valid input, not an off-by-one rejection."""
    r = await client.post(
        "/api/v1/users",
        headers=auth_headers,
        json={"email": "boundary@example.com", "password": "A" * 72, "role": "analyst"},
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_failed_hash_does_not_revoke_sessions(client, monkeypatch):
    """The ordering invariant: hashing happens before the epoch bump.

    Forces hash_password to fail and asserts the caller's refresh token still
    works. With the old ordering the epoch was already bumped, so the token was
    dead even though the password had not changed.
    """
    from scanr.api.v1 import users as users_api

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "testadminpass123"},
    )
    assert login.status_code == 200, login.text
    refresh_token = login.cookies.get("scanr_rt")
    access = login.json()["access_token"]

    def _boom(_plain: str) -> str:
        raise ValueError("simulated hashing failure")

    monkeypatch.setattr(users_api, "hash_password", _boom)

    with pytest.raises(ValueError):
        await client.post(
            "/api/v1/users/me/change-password",
            headers={"Authorization": f"Bearer {access}"},
            json={"current_password": "testadminpass123", "new_password": "a-valid-new-password"},
        )

    monkeypatch.undo()

    # The session must have survived: the password never changed, so revoking
    # every refresh token would be a pure loss for the user.
    r = await client.post("/api/v1/auth/refresh", cookies={"scanr_rt": refresh_token})
    assert r.status_code == 200, r.text

    # And the original password must still work.
    relogin = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@scanr.local", "password": "testadminpass123"},
    )
    assert relogin.status_code == 200, relogin.text
