from __future__ import annotations

from collections.abc import Iterable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.auth.jwt_handler import decode_token
from scanr.db.session import get_db
from scanr.models.user import User

bearer = HTTPBearer(auto_error=False)

# All valid API key scopes
ALL_SCOPES = frozenset({
    "scans:read",
    "scans:write",
    "findings:read",
    "findings:triage",
    "reports:read",     # list/inspect/download an existing report
    "reports:create",   # generate a new report (spawns a background job)
    "reports:export",   # legacy: implies reports:read + reports:create
    "ai:generate",      # spend LLM budget: summaries, narratives, FP testing
    "credentials:read",
    "credentials:write",
    "plugins:read",
    "plugins:write",
    "agents:read",
    "agents:write",
    "api_keys:read",
    "api_keys:write",
    "webhooks:read",
    "webhooks:write",
    "wordlists:read",
    "wordlists:write",
    "host_tags:read",
    "host_tags:write",
    "*",
})

# Scopes retained only so existing API keys keep working, mapped to the scopes
# that replaced them. 'reports:export' used to gate report creation *and*
# download; those are now separate, because downloading a report you can already
# see is a read while generating one spawns a background job.
_SCOPE_ALIASES: dict[str, frozenset[str]] = {
    "reports:export": frozenset({"reports:read", "reports:create"}),
}

# Scopes that should never be issued to a new key (superseded, but still honoured
# on keys that already hold them).
DEPRECATED_SCOPES = frozenset(_SCOPE_ALIASES)


def expand_scopes(scopes: "Iterable[str]") -> set[str]:
    """Resolve legacy aliases to the scopes they stand for, keeping the originals.

    Used both for permission checks and for the key-minting containment check, so
    a key holding a legacy scope is treated consistently in both.
    """
    out: set[str] = set()
    for scope in scopes:
        out.add(scope)
        out |= _SCOPE_ALIASES.get(scope, frozenset())
    return out


def _has_scope(scopes: list[str], required: str) -> bool:
    if "*" in scopes:
        return True
    return required in expand_scopes(scopes)


def _viewer_may_use(scope: str) -> bool:
    """A read-only ('viewer') account may exercise read scopes only.

    Derived rather than hand-listed, so a newly added ':write'/':create'/
    ':triage'/':generate' scope is denied to viewers by default instead of being
    silently granted. Note this is why report *download* is gated on
    reports:read: a read-only account whose whole purpose is reading results has
    to be able to fetch them, and the report contains nothing the findings list
    does not already expose.
    """
    return scope.endswith(":read")


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    token: str | None = None

    if credentials:
        token = credentials.credentials

    api_key_header = request.headers.get("X-API-Key")

    if api_key_header:
        from scanr.auth.api_key_auth import get_user_from_api_key
        user, scopes = await get_user_from_api_key(api_key_header, db)
        if user:
            request.state.scopes = scopes
            return user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    if token and token.startswith("sk_") and len(token) > 20:
        from scanr.auth.api_key_auth import get_user_from_api_key
        user, scopes = await get_user_from_api_key(token, db)
        if user:
            request.state.scopes = scopes
            return user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = decode_token(token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id: str = payload.get("sub", "")
    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Interactive (JWT) sessions are granted the full scope set: scopes are an
    # API-key concept used to restrict automation tokens, not a per-role limit
    # on the web UI. Role-based authorization (e.g. require_admin) is still
    # enforced separately on top of this for privileged endpoints.
    request.state.scopes = ["*"]
    return user


def require_scope(scope: str):
    """Return a FastAPI dependency that enforces a scope AND the caller's role.

    Two independent checks, because they constrain different things:
      * scope — restricts what an automation (API key) token may do. Interactive
        JWT sessions hold '*', so this is a no-op for them.
      * role  — restricts what the *user* may do regardless of token type. A
        'viewer' is read-only, so a mutating scope is refused even though the
        JWT session nominally holds every scope.
    """
    async def _check(request: Request, user: User = Depends(get_current_user)) -> User:
        scopes: list[str] = getattr(request.state, "scopes", [])
        if not _has_scope(scopes, scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key is missing required scope: '{scope}'",
            )
        if user.role == "viewer" and not _viewer_may_use(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account is read-only (viewer role).",
            )
        return user
    return _check


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    return current_user
