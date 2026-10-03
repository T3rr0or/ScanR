"""Audit trail: who changed what, from where, and whether it was allowed.

Two sources feed one table:

* ``AuditMiddleware`` records every state-changing API request (POST, PUT,
  PATCH, DELETE) plus a few sensitive reads (report downloads, exports), so a
  new endpoint is covered without anyone remembering to add a call.
* ``record`` is called explicitly where the middleware cannot see enough,
  chiefly sign-in, where a failed attempt has no authenticated user.

Request bodies are never stored: they carry passwords, API keys and scan
credentials. Entries are written in their own session so they persist even when
the request's own transaction rolls back.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
# Reads worth recording: data leaving the system in bulk.
_AUDITED_READS = (
    re.compile(r"^/api/v1/reports/[^/]+/download$"),
    re.compile(r"^/api/v1/findings/export$"),
    re.compile(r"^/api/v1/audit/export$"),
)
# Recorded explicitly (with the email involved) or pure session plumbing.
_SKIPPED = {"/api/v1/auth/login", "/api/v1/auth/login/mfa", "/api/v1/auth/refresh", "/api/v1/auth/logout"}
_VERBS = {"POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete", "GET": "read"}


def client_ip(request: Request) -> str:
    from scanr.core.limiter import _real_ip

    return _real_ip(request)


def action_for(method: str, route_path: str) -> tuple[str, str | None]:
    """Name an API call: POST /api/v1/scans/{scan_id}/launch -> ("scans.launch", "scans")."""
    parts = [p for p in route_path.removeprefix("/api/v1").split("/") if p]
    statics = [p.replace("-", "_") for p in parts if not p.startswith("{")]
    if not statics:
        return method.lower(), None
    resource = statics[0]
    # POST /scans/{id}/launch and GET /reports/{id}/download name their action
    # in the last segment; everything else is the resource plus the verb.
    if method in ("POST", "GET") and len(statics) > 1 and not parts[-1].startswith("{"):
        return ".".join(statics), resource
    return ".".join(statics + [_VERBS.get(method, method.lower())]), resource


async def write(
    *,
    action: str,
    user_id: str | None = None,
    user_email: str | None = None,
    auth_method: str | None = None,
    ip: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
    status_code: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Persist one event. Never raises: auditing must not break the request."""
    from scanr.db.session import AsyncSessionLocal
    from scanr.models.audit_event import AuditEvent

    try:
        async with AsyncSessionLocal() as db:
            db.add(AuditEvent(
                action=action[:100],
                user_id=user_id,
                user_email=user_email,
                auth_method=auth_method,
                ip=(ip or "")[:64] or None,
                target_type=target_type,
                target_id=(target_id or "")[:100] or None,
                method=method,
                path=(path or "")[:300] or None,
                status_code=status_code,
                details=json.dumps(details, default=str)[:4000] if details else None,
            ))
            await db.commit()
    except Exception:
        logger.exception("Could not write audit event %s", action)


async def record(request: Request | None, action: str, *, user: Any = None, email: str | None = None,
                 target_type: str | None = None, target_id: str | None = None,
                 status_code: int | None = None, details: dict[str, Any] | None = None) -> None:
    await write(
        action=action,
        user_id=getattr(user, "id", None),
        user_email=getattr(user, "email", None) or email,
        auth_method="session" if user is not None else None,
        ip=client_ip(request) if request is not None else None,
        target_type=target_type,
        target_id=target_id,
        method=request.method if request is not None else None,
        path=request.url.path if request is not None else None,
        status_code=status_code,
        details=details,
    )


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        try:
            await self._maybe_record(request, response)
        except Exception:
            logger.exception("Audit middleware failed")
        return response

    async def _maybe_record(self, request: Request, response: Response) -> None:
        path = request.url.path
        if not path.startswith("/api/v1/") or path in _SKIPPED:
            return
        method = request.method
        if method not in _MUTATING and not (method == "GET" and any(p.match(path) for p in _AUDITED_READS)):
            return
        user_id = getattr(request.state, "user_id", None)
        if user_id is None and response.status_code == 401:
            return  # anonymous noise; failed sign-ins are recorded explicitly
        route = request.scope.get("route")
        template = getattr(route, "path", path)
        action, resource = action_for(method, template)
        params = request.scope.get("path_params") or {}
        await write(
            action=action,
            user_id=user_id,
            user_email=getattr(request.state, "user_email", None),
            auth_method=getattr(request.state, "auth_method", None),
            ip=client_ip(request),
            target_type=resource,
            target_id=next(iter(params.values()), None),
            method=method,
            path=path,
            status_code=response.status_code,
            details={k: v for k, v in request.query_params.items() if k not in {"token", "api_key"}} or None,
        )
