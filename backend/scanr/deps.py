from __future__ import annotations

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
    "reports:read",
    "reports:export",
    "credentials:read",
    "credentials:write",
    "plugins:read",
    "plugins:write",
    "agents:read",
    "agents:write",
    "*",
})


def _has_scope(scopes: list[str], required: str) -> bool:
    return "*" in scopes or required in scopes


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

    if token and token.startswith("sk_") and not token.startswith("sk_agent_"):
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

    user_id: str = payload.get("sub", "")
    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # JWT users always get full access
    request.state.scopes = ["*"]
    return user


def require_scope(scope: str):
    """Return a FastAPI dependency that enforces a specific scope on API key auth."""
    async def _check(request: Request, user: User = Depends(get_current_user)) -> User:
        scopes: list[str] = getattr(request.state, "scopes", ["*"])
        if not _has_scope(scopes, scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key is missing required scope: '{scope}'",
            )
        return user
    return _check


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    return current_user
