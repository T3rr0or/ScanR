from __future__ import annotations

from fastapi import HTTPException, status

from scanr.models.user import UserRole


def require_role(*allowed: UserRole):
    """Return a FastAPI dependency that enforces role membership."""

    def checker(current_user_role: str) -> None:
        if current_user_role not in [r.value for r in allowed]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {[r.value for r in allowed]}",
            )

    return checker
