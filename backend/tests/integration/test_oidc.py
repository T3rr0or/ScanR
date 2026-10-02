"""Single sign-on against an in-process fake OpenID provider."""
from __future__ import annotations

import time
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk, jwt

from scanr.auth import oidc
from scanr.config import get_settings

ISSUER = "https://idp.example.com/tenant"
CLIENT_ID = "scanr-client"


class FakeProvider:
    def __init__(self) -> None:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_pem = private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        public_pem = private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.jwk = {**jwk.construct(public_pem, "RS256").to_dict(), "kid": "k1", "use": "sig"}
        self.claims: dict = {}
        self.token_requests: list[dict] = []
        self.nonce: str | None = None

    def id_token(self, **overrides) -> str:
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "subject-1",
            "email": "sso-user@example.com",
            "email_verified": True,
            "nonce": self.nonce,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            **self.claims,
            **overrides,
        }
        return jwt.encode(claims, self.private_pem, algorithm="RS256", headers={"kid": "k1"})

    async def get_json(self, url: str, **kwargs):
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/keys",
            }
        if url.endswith("/keys"):
            return {"keys": [self.jwk]}
        if url.endswith("/token"):
            self.token_requests.append(kwargs)
            return {"id_token": self.id_token(), "token_type": "Bearer"}
        raise AssertionError(url)


@pytest.fixture
def provider(monkeypatch):
    fake = FakeProvider()
    settings = get_settings()
    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "oidc_client_id", CLIENT_ID)
    monkeypatch.setattr(settings, "oidc_client_secret", "shh")
    monkeypatch.setattr(settings, "oidc_auto_create_users", False)
    monkeypatch.setattr(settings, "oidc_allowed_domains", "")
    monkeypatch.setattr(oidc, "_get_json", fake.get_json)
    oidc.reset_cache()
    yield fake
    oidc.reset_cache()


async def _start(client, provider) -> str:
    resp = await client.get("/api/v1/auth/oidc/login")
    assert resp.status_code == 303, resp.text
    location = urlparse(resp.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == f"{ISSUER}/authorize"
    query = parse_qs(location.query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == ["http://localhost/api/v1/auth/oidc/callback"]
    provider.nonce = query["nonce"][0]
    return query["state"][0]


async def _callback(client, state: str, **params):
    return await client.get("/api/v1/auth/oidc/callback", params={"code": "abc", "state": state, **params})


def _sso_result(resp) -> dict[str, list[str]]:
    assert resp.status_code == 303, resp.text
    location = urlparse(resp.headers["location"])
    assert location.path == "/login"
    return parse_qs(location.query)


@pytest.mark.asyncio
async def test_config_reports_disabled_by_default(client):
    resp = await client.get("/api/v1/auth/oidc/config")
    assert resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_disabled_login_redirects_with_error(client):
    resp = await client.get("/api/v1/auth/oidc/login")
    assert _sso_result(resp) == {"sso_error": ["disabled"]}


@pytest.mark.asyncio
async def test_unknown_user_refused_without_auto_create(client, provider):
    provider.claims = {"sub": f"nobody-{uuid.uuid4().hex}", "email": f"{uuid.uuid4().hex}@example.com"}
    state = await _start(client, provider)
    resp = await _callback(client, state)
    assert _sso_result(resp) == {"sso_error": ["no_account"]}
    assert "scanr_rt" not in resp.cookies


@pytest.mark.asyncio
async def test_existing_user_is_linked_and_signed_in(client, auth_headers, provider):
    email = f"linked-{uuid.uuid4().hex[:8]}@example.com"
    created = await client.post(
        "/api/v1/users", json={"email": email, "password": "long-enough-pw", "role": "analyst"}, headers=auth_headers
    )
    assert created.status_code == 201
    subject = f"sub-{uuid.uuid4().hex}"
    provider.claims = {"sub": subject, "email": email.upper()}

    state = await _start(client, provider)
    resp = await _callback(client, state)
    assert _sso_result(resp) == {"sso": ["success"]}
    assert "scanr_rt" in resp.cookies
    assert provider.token_requests[-1]["data"]["code_verifier"]

    refreshed = await client.post("/api/v1/auth/refresh", cookies={"scanr_rt": resp.cookies["scanr_rt"]})
    assert refreshed.status_code == 200
    me = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {refreshed.json()['access_token']}"})
    assert me.json()["email"] == email

    # Linked by subject: an email change at the provider still reaches this account.
    provider.claims = {"sub": subject, "email": f"renamed-{uuid.uuid4().hex[:6]}@example.com"}
    state = await _start(client, provider)
    assert _sso_result(await _callback(client, state)) == {"sso": ["success"]}

    # ...and a different subject presenting the original email cannot take it over.
    provider.claims = {"sub": f"other-{uuid.uuid4().hex}", "email": email}
    state = await _start(client, provider)
    assert _sso_result(await _callback(client, state)) == {"sso_error": ["account_conflict"]}


@pytest.mark.asyncio
async def test_auto_create_uses_default_role_and_domain_filter(client, auth_headers, provider, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "oidc_auto_create_users", True)
    monkeypatch.setattr(settings, "oidc_allowed_domains", "corp.example")

    provider.claims = {"sub": f"s-{uuid.uuid4().hex}", "email": f"{uuid.uuid4().hex[:8]}@elsewhere.example"}
    state = await _start(client, provider)
    assert _sso_result(await _callback(client, state)) == {"sso_error": ["domain_not_allowed"]}

    email = f"{uuid.uuid4().hex[:8]}@corp.example"
    provider.claims = {"sub": f"s-{uuid.uuid4().hex}", "email": email, "name": "New Person"}
    state = await _start(client, provider)
    assert _sso_result(await _callback(client, state)) == {"sso": ["success"]}
    users = {u["email"]: u for u in (await client.get("/api/v1/users", headers=auth_headers)).json()}
    assert users[email]["role"] == "viewer"
    assert users[email]["full_name"] == "New Person"


@pytest.mark.asyncio
async def test_unverified_email_is_not_linked(client, auth_headers, provider):
    email = f"unverified-{uuid.uuid4().hex[:8]}@example.com"
    await client.post("/api/v1/users", json={"email": email, "password": "long-enough-pw"}, headers=auth_headers)
    provider.claims = {"sub": f"s-{uuid.uuid4().hex}", "email": email, "email_verified": False}
    state = await _start(client, provider)
    assert _sso_result(await _callback(client, state)) == {"sso_error": ["email_unverified"]}


@pytest.mark.asyncio
async def test_state_must_match_browser_cookie_and_is_single_use(client, provider):
    state = await _start(client, provider)
    forged = await client.get(
        "/api/v1/auth/oidc/callback", params={"code": "abc", "state": state}, cookies={"scanr_oidc_state": "other"}
    )
    assert _sso_result(forged) == {"sso_error": ["invalid_state"]}

    provider.claims = {"sub": "s", "email": f"{uuid.uuid4().hex}@example.com"}
    await _callback(client, state)  # consumes the state, whatever the outcome
    replay = await _callback(client, state)
    assert _sso_result(replay) == {"sso_error": ["invalid_state"]}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "someone-else"},
        {"iss": "https://evil.example.com"},
        {"nonce": "wrong"},
        {"exp": int(time.time()) - 600},
    ],
)
async def test_invalid_id_tokens_are_rejected(client, provider, overrides):
    state = await _start(client, provider)
    original = provider.id_token
    provider.id_token = lambda **kw: original(**{**overrides, **kw})  # type: ignore[method-assign]
    assert _sso_result(await _callback(client, state)) == {"sso_error": ["invalid_token"]}


@pytest.mark.asyncio
async def test_hmac_signed_token_is_rejected(provider):
    provider.nonce = "n"
    forged = jwt.encode(
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "x", "nonce": "n", "exp": int(time.time()) + 60},
        "shh",
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(oidc.OIDCError) as err:
        await oidc.validate_id_token(forged, "n", None)
    assert err.value.code == "invalid_token"
