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
    "ai:agent",         # launch/control guided or autonomous AI agent runs
    "ai:aggressive",    # opt into exploitation, command execution and target egress
    "ai:configure",     # administer provider keys, defaults and model selection
    "credentials:read",
    "credentials:write",
    "plugins:read",
    "plugins:write",
    "users:manage",
    "integrations:manage",
    "system:manage",
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
    "audit:read",
    "*",
})

AUTH_METHOD_API_KEY = "api_key"
AUTH_METHOD_SESSION = "session"


def _remember_identity(request: Request, user: User) -> None:
    """Expose the caller to scanr.core.audit.AuditMiddleware."""
    request.state.user_id = user.id
    request.state.user_email = user.email

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


def ensure_scopes(request: Request, user: User, *required_scopes: str) -> User:
    """Enforce one or more API-key scopes and the caller's role.

    This is the imperative counterpart to :func:`require_scopes`, used when a
    permission is conditional on the validated request body (for example an AI
    run that requests aggressive capabilities). Keeping both paths on this one
    implementation prevents conditional checks from drifting away from the
    normal FastAPI dependency semantics.
    """
    if not required_scopes:
        raise ValueError("At least one required scope must be supplied")

    scopes: list[str] = getattr(request.state, "scopes", [])
    for required in required_scopes:
        if not _has_scope(scopes, required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key is missing required scope: '{required}'",
            )

    if user.role == "viewer" and any(
        not _viewer_may_use(required) for required in required_scopes
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is read-only (viewer role).",
        )
    return user


def ensure_admin(user: User) -> User:
    """Enforce the account-level administrator role."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin required",
        )
    return user


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
            request.state.auth_method = AUTH_METHOD_API_KEY
            _remember_identity(request, user)
            return user
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    if token and token.startswith("sk_") and len(token) > 20:
        from scanr.auth.api_key_auth import get_user_from_api_key
        user, scopes = await get_user_from_api_key(token, db)
        if user:
            request.state.scopes = scopes
            request.state.auth_method = AUTH_METHOD_API_KEY
            _remember_identity(request, user)
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
    # on the web UI. Role-based authorization (require_admin_scope or the
    # session-only require_session_admin) is still enforced separately for
    # privileged endpoints.
    request.state.scopes = ["*"]
    request.state.auth_method = AUTH_METHOD_SESSION
    _remember_identity(request, user)
    return user


def require_scopes(*scopes: str):
    """Return a dependency enforcing every scope and the caller's role.

    Two independent checks, because they constrain different things:
      * scope — restricts what an automation (API key) token may do. Interactive
        JWT sessions hold '*', so this is a no-op for them.
      * role  — restricts what the *user* may do regardless of token type. A
        'viewer' is read-only, so a mutating scope is refused even though the
        JWT session nominally holds every scope.
    """
    if not scopes:
        raise ValueError("At least one required scope must be supplied")

    async def _check(request: Request, user: User = Depends(get_current_user)) -> User:
        return ensure_scopes(request, user, *scopes)

    return _check


def require_scope(scope: str):
    """Backward-compatible single-scope form of :func:`require_scopes`."""
    return require_scopes(scope)


def require_admin_scope(scope: str):
    """Require both an explicit API-key scope and the administrator role.

    JWT sessions hold ``*`` and therefore only need the role check. API keys,
    including keys owned by an administrator, must have the named permission.
    """
    async def _check(request: Request, user: User = Depends(get_current_user)) -> User:
        ensure_scopes(request, user, scope)
        return ensure_admin(user)

    return _check


async def require_session_user(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """Require an interactive user session, never an API key."""
    if getattr(request.state, "auth_method", None) != AUTH_METHOD_SESSION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Interactive user session required",
        )
    return current_user


async def require_session_admin(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """Require an interactive administrator session, never an API key.

    Reserved for operations such as in-process self-update where even a broadly
    scoped, long-lived automation credential is an inappropriate authority.
    """
    ensure_admin(current_user)
    if getattr(request.state, "auth_method", None) != AUTH_METHOD_SESSION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Interactive admin session required",
        )
    return current_user
