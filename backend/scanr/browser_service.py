"""Secret-free renderer for hostile scan targets.

The API/worker never launches Chromium in production.  It sends a tightly
bounded request here instead; this process has no database, Redis, JWT, vault,
provider, or sandbox-control credentials.  DNS is resolved once and pinned into
Chromium, and browser traffic is restricted to the exact requested origin.
"""
from __future__ import annotations

import asyncio
import base64
import os
import secrets
import socket
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from scanr.core.browser import _observe_url_local
from scanr.utils.ip_utils import canonical_ip, is_forbidden_target

app = FastAPI(
    title="ScanR isolated browser",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_TOKEN = os.environ.get("BROWSER_SERVICE_TOKEN", "")
_DENYLIST = {
    value.strip().lower()
    for value in os.environ.get(
        "SCAN_TARGET_DENYLIST", "localhost,postgres,redis,db,scanr-api,scanr-worker"
    ).split(",")
    if value.strip()
}
_MAX_SCREENSHOT = 5 * 1024 * 1024


class ObserveRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    canary: str = Field(default="", max_length=256)
    timeout_ms: int = Field(default=15_000, ge=500, le=30_000)
    settle_seconds: float = Field(default=1.5, ge=0, le=5)
    overall_timeout: float = Field(default=60, ge=1, le=75)
    java_script_enabled: bool = True
    screenshot: bool = False


def _check_token(candidate: str | None) -> None:
    if not _TOKEN or not candidate:
        raise HTTPException(status_code=401, detail="invalid browser token")
    if not secrets.compare_digest(candidate.encode(), _TOKEN.encode()):
        raise HTTPException(status_code=401, detail="invalid browser token")


async def _resolve_authorized(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="only absolute HTTP(S) URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(status_code=400, detail="URL userinfo is not allowed")
    hostname = parsed.hostname.rstrip(".").lower()
    if is_forbidden_target(hostname, _DENYLIST):
        raise HTTPException(status_code=403, detail="browser target is denied")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid browser target port") from exc
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM
        )
    except (OSError, UnicodeError) as exc:
        raise HTTPException(status_code=400, detail="browser target did not resolve") from exc
    addresses = sorted({canonical_ip(info[4][0]) or info[4][0] for info in infos})
    if not addresses:
        raise HTTPException(status_code=400, detail="browser target did not resolve")
    # Reject mixed answers rather than selecting the safe-looking one: otherwise
    # resolver order becomes a bypass primitive.
    if any(is_forbidden_target(address, _DENYLIST) for address in addresses):
        raise HTTPException(status_code=403, detail="browser target resolved to a denied address")
    return hostname, addresses[0]


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/observe")
async def observe(
    body: ObserveRequest,
    x_browser_token: str | None = Header(default=None),
) -> dict:
    _check_token(x_browser_token)
    pinned_host = await _resolve_authorized(body.url)
    screenshot_path: str | None = None
    if body.screenshot:
        handle = tempfile.NamedTemporaryFile(prefix="scanr-browser-", suffix=".png", delete=False)
        screenshot_path = handle.name
        handle.close()
    try:
        result = await _observe_url_local(
            body.url,
            body.canary,
            timeout_ms=body.timeout_ms,
            settle_seconds=body.settle_seconds,
            screenshot_path=screenshot_path,
            overall_timeout=body.overall_timeout,
            java_script_enabled=body.java_script_enabled,
            pinned_host=pinned_host,
        )
        result["screenshot_b64"] = None
        if screenshot_path and result.get("screenshot"):
            raw = await asyncio.to_thread(Path(screenshot_path).read_bytes)
            if len(raw) > _MAX_SCREENSHOT:
                result["error"] = "screenshot exceeded 5 MiB"
            else:
                result["screenshot_b64"] = base64.b64encode(raw).decode("ascii")
        # Never disclose a path inside the sidecar.
        result["screenshot"] = None
        return result
    finally:
        if screenshot_path:
            Path(screenshot_path).unlink(missing_ok=True)
