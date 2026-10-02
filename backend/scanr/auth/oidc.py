"""OpenID Connect authorization-code login (with PKCE) against an external IdP.

Only the pieces ScanR needs: discovery, the authorize URL, the code exchange and
ID-token validation. Users are linked to the provider by issuer + subject after
their first login, so a later email change at the provider cannot move a login
onto a different ScanR account.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
from jose import jwt
from jose.exceptions import JOSEError

from scanr.config import get_settings

# Asymmetric only: an HMAC algorithm here would let the client secret, which
# the provider also knows, sign tokens — and would invite key confusion.
ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
_CACHE_SECONDS = 3600
_HTTP_TIMEOUT = 10.0


class OIDCError(Exception):
    """Login could not be completed. ``code`` is safe to show in a URL."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code


@dataclass
class Identity:
    subject: str  # "<issuer>|<sub>", unique across providers
    email: str
    email_verified: bool | None
    name: str | None


_discovery: tuple[float, dict[str, Any]] | None = None
_jwks: tuple[float, dict[str, Any]] | None = None


def reset_cache() -> None:
    global _discovery, _jwks
    _discovery = None
    _jwks = None


def _issuer() -> str:
    return get_settings().oidc_issuer.rstrip("/")


def _require_https(url: str) -> None:
    settings = get_settings()
    if not url.startswith("https://") and not settings.development_mode:
        raise OIDCError("provider_misconfigured", f"OIDC endpoint must use HTTPS: {url}")


async def _get_json(url: str, **kwargs: Any) -> dict[str, Any]:
    _require_https(url)
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
        try:
            response = await client.request(kwargs.pop("method", "GET"), url, **kwargs)
        except httpx.HTTPError as exc:
            raise OIDCError("provider_unreachable", f"{url}: {exc}") from exc
    if response.status_code >= 400:
        raise OIDCError("provider_error", f"{url} returned HTTP {response.status_code}: {response.text[:300]}")
    try:
        data = response.json()
    except ValueError as exc:
        raise OIDCError("provider_error", f"{url} did not return JSON") from exc
    if not isinstance(data, dict):
        raise OIDCError("provider_error", f"{url} did not return a JSON object")
    return data


async def discovery() -> dict[str, Any]:
    global _discovery
    if _discovery and time.monotonic() - _discovery[0] < _CACHE_SECONDS:
        return _discovery[1]
    data = await _get_json(f"{_issuer()}/.well-known/openid-configuration")
    # OpenID Connect Discovery §4.3: the document must name the issuer that was
    # asked for, otherwise tokens could be accepted from a different tenant.
    if str(data.get("issuer", "")).rstrip("/") != _issuer():
        raise OIDCError("provider_misconfigured", f"discovery issuer {data.get('issuer')!r} != OIDC_ISSUER")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not data.get(field):
            raise OIDCError("provider_misconfigured", f"discovery document lacks {field}")
    _discovery = (time.monotonic(), data)
    return data


async def _signing_keys(force: bool = False) -> dict[str, Any]:
    global _jwks
    if not force and _jwks and time.monotonic() - _jwks[0] < _CACHE_SECONDS:
        return _jwks[1]
    data = await _get_json((await discovery())["jwks_uri"])
    _jwks = (time.monotonic(), data)
    return data


def new_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


async def authorization_url(state: str, nonce: str, code_challenge: str) -> str:
    settings = get_settings()
    endpoint = (await discovery())["authorization_endpoint"]
    _require_https(endpoint)
    query = urlencode({
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_callback_url,
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{query}"


async def exchange_code(code: str, code_verifier: str) -> dict[str, Any]:
    settings = get_settings()
    meta = await discovery()
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_callback_url,
        "code_verifier": code_verifier,
    }
    methods = meta.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    kwargs: dict[str, Any] = {"method": "POST", "headers": {"Accept": "application/json"}}
    if "client_secret_basic" in methods:
        kwargs["auth"] = (settings.oidc_client_id, settings.oidc_client_secret)
    else:
        form.update(client_id=settings.oidc_client_id, client_secret=settings.oidc_client_secret)
    kwargs["data"] = form
    tokens = await _get_json(meta["token_endpoint"], **kwargs)
    if not tokens.get("id_token"):
        raise OIDCError("provider_error", "token response has no id_token")
    return tokens


async def _key_for(token: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except JOSEError as exc:
        raise OIDCError("invalid_token", "malformed ID token") from exc
    if header.get("alg") not in ALLOWED_ALGORITHMS:
        raise OIDCError("invalid_token", f"ID token algorithm {header.get('alg')!r} is not allowed")
    kid = header.get("kid")
    for force in (False, True):  # refetch once: the provider may have rotated keys
        keys = (await _signing_keys(force=force)).get("keys", [])
        matches = [k for k in keys if isinstance(k, dict) and (kid is None or k.get("kid") == kid)]
        if len(matches) == 1:
            return matches[0]
    raise OIDCError("invalid_token", "no matching signing key for ID token")


async def validate_id_token(id_token: str, nonce: str, access_token: str | None) -> Identity:
    settings = get_settings()
    key = await _key_for(id_token)
    try:
        claims = jwt.decode(
            id_token,
            key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=settings.oidc_client_id,
            issuer=(await discovery())["issuer"],
            access_token=access_token,
        )
    except JOSEError as exc:
        raise OIDCError("invalid_token", str(exc)) from exc
    if not claims.get("nonce") or not secrets.compare_digest(str(claims["nonce"]), nonce):
        raise OIDCError("invalid_token", "ID token nonce mismatch")
    if not claims.get("sub"):
        raise OIDCError("invalid_token", "ID token has no subject")

    email = claims.get("email")
    if not email:
        # Entra ID puts the sign-in name here when no mail attribute is set.
        candidate = claims.get("preferred_username") or claims.get("upn")
        email = candidate if candidate and "@" in str(candidate) else None
    if not email:
        raise OIDCError("no_email", "the provider did not return an email address (add the 'email' scope)")
    verified = claims.get("email_verified")
    if isinstance(verified, str):
        verified = verified.lower() == "true"
    return Identity(
        subject=f"{claims['iss']}|{claims['sub']}"[:255],
        email=str(email).lower().strip(),
        email_verified=verified if isinstance(verified, bool) else None,
        name=claims.get("name"),
    )
