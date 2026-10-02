from __future__ import annotations

import logging
import asyncio
import json
import os
import shlex
import subprocess
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import Integer, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.db import get_db
from scanr.deps import (
    get_current_user,
    require_admin_scope,
    require_scope,
    require_session_admin,
)
from scanr.models import Scan, ScanStatus
from scanr.models.user import User

router = APIRouter(prefix="/system", tags=["system"])
logger = logging.getLogger(__name__)
settings = get_settings()
UPDATE_STATUS_KEY = "scanr:update:status"
UPDATE_LOCK_KEY = "scanr:update:lock"
UPDATE_LOCK_TTL = 3600
# Identifies this API process. An update started by a different process that is
# still marked in progress was interrupted by an API restart.
_API_INSTANCE = uuid.uuid4().hex


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_update_status() -> dict:
    return {
        "enabled": settings.self_update_enabled,
        "state": "idle",
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "message": None,
        "log": "",
    }


async def _get_update_status() -> dict:
    try:
        from scanr.db.redis import get_redis
        r = get_redis()
        raw = await r.get(UPDATE_STATUS_KEY)
        if raw:
            data = json.loads(raw)
            data["enabled"] = settings.self_update_enabled
            owner = data.get("api_instance")
            if data.get("state") in ("running", "queued", "restarting") and owner and owner != _API_INSTANCE:
                # This API process is not the one that ran the update, so the
                # API was replaced. After "restarting", the replacement serving
                # this request verifies the restart; earlier, the job was killed.
                if data["state"] == "restarting":
                    data.update({
                        "state": "succeeded",
                        "exit_code": 0,
                        "message": f"Services restarted. ScanR v{settings.app_version} is running.",
                    })
                else:
                    data.update({
                        "state": "failed",
                        "message": "The API restarted before the update finished.",
                    })
                data["finished_at"] = _utc_now()
                await _set_update_status(data)
                await r.delete(UPDATE_LOCK_KEY)
            # A restart can terminate this process before it records completion.
            elif data.get("state") in ("running", "queued", "restarting") and data.get("started_at"):
                from datetime import datetime, timezone, timedelta
                try:
                    started = datetime.fromisoformat(data["started_at"])
                    if datetime.now(timezone.utc) - started > timedelta(seconds=UPDATE_LOCK_TTL):
                        data["state"] = "failed"
                        data["finished_at"] = _utc_now()
                        data["message"] = "Update timed out (process likely died during container restart)."
                        await _set_update_status(data)
                except Exception:
                    pass
            return data
    except Exception:
        logger.debug("Could not read update status", exc_info=True)
    return _default_update_status()


async def _set_update_status(data: dict) -> None:
    data["enabled"] = settings.self_update_enabled
    try:
        from scanr.db.redis import get_redis
        r = get_redis()
        await r.setex(UPDATE_STATUS_KEY, 86400, json.dumps(data))
    except Exception:
        logger.debug("Could not persist update status", exc_info=True)


def _split_update_command(command: str) -> list[list[str]]:
    parts: list[list[str]] = []
    for segment in command.split("&&"):
        argv = shlex.split(segment.strip())
        if argv:
            parts.append(argv)
    if not parts:
        raise ValueError("Update command is empty")
    return parts


def _is_restart_cmd(argv: list[str]) -> bool:
    return any(a in ('up', 'restart') for a in argv)


async def _run_self_update(lock_token: str) -> None:
    status = {
        "enabled": settings.self_update_enabled,
        "state": "running",
        "api_instance": _API_INSTANCE,
        "started_at": _utc_now(),
        "finished_at": None,
        "exit_code": None,
        "message": "Update started",
        "log": "",
    }
    await _set_update_status(status)

    logs: list[str] = []
    exit_code = 0
    try:
        workdir = settings.self_update_workdir
        if not workdir.exists():
            raise RuntimeError(f"Update directory does not exist: {workdir}")

        # Run with a minimal environment rather than copying the whole process
        # environment (which holds SECRET_KEY, VAULT_KEY, DB and admin
        # passwords). docker compose reads .env from the workdir, so the
        # secrets it needs are still available without exposing the API's.
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/app"),
        }
        commands = _split_update_command(settings.self_update_command)

        for i, argv in enumerate(commands):
            is_last = i == len(commands) - 1
            logs.append(f"$ {' '.join(shlex.quote(x) for x in argv)}")

            if is_last and _is_restart_cmd(argv):
                # The API may be replaced by this command. Persist an honest
                # intermediate state; dispatch is not evidence of success.
                status.update({
                    "state": "restarting",
                    "message": "Restarting services. Waiting for the new API to respond.",
                    "log": "\n".join(logs)[-12000:],
                })
                await _set_update_status(status)

            # subprocess.run is blocking. Keep it off the API event loop so
            # health checks and status polling remain available during pulls.
            proc = await asyncio.to_thread(
                subprocess.run,
                argv,
                cwd=workdir,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=900,
            )
            output = (proc.stdout or "").strip()
            if output:
                logs.append(output[-8000:])
            exit_code = proc.returncode
            if proc.returncode != 0:
                raise RuntimeError(f"Command exited with code {proc.returncode}: {' '.join(argv)}")

        status.update({
            "state": "succeeded",
            "finished_at": _utc_now(),
            "exit_code": exit_code,
            "message": "Update completed.",
            "log": "\n".join(logs)[-12000:],
        })
    except Exception as exc:
        logger.exception("Self-update failed")
        status.update({
            "state": "failed",
            "finished_at": _utc_now(),
            "exit_code": exit_code or 1,
            "message": str(exc),
            "log": "\n".join(logs)[-12000:],
        })
    await _set_update_status(status)
    from scanr.db.redis import get_redis
    # Never remove a newer request's lock if this job outlived its lease.
    await get_redis().eval(
        "if redis.call('get', KEYS[1]) == ARGV[1] then "
        "return redis.call('del', KEYS[1]) else return 0 end",
        1, UPDATE_LOCK_KEY, lock_token,
    )


@router.get("/health")
async def health():
    return {"status": "ok", "service": "scanr"}


@router.get("/stats")
async def stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:read")),
):
    uid = current_user.id

    # Scan counts in one query
    scan_row = (await db.execute(
        select(
            func.count(Scan.id).label("total"),
            func.sum(cast(Scan.status == ScanStatus.running, Integer)).label("running"),
            func.sum(cast(Scan.status == ScanStatus.completed, Integer)).label("completed"),
            func.sum(Scan.hosts_up).label("hosts_total"),
            func.sum(
                Scan.findings_info + Scan.findings_low + Scan.findings_medium +
                Scan.findings_high + Scan.findings_critical
            ).label("findings_total"),
            func.sum(Scan.findings_critical).label("findings_critical"),
        ).where(Scan.user_id == uid)
    )).one()

    return {
        "scans_total": scan_row.total or 0,
        "scans_running": scan_row.running or 0,
        "scans_completed": scan_row.completed or 0,
        "hosts_total": scan_row.hosts_total or 0,
        "findings_total": scan_row.findings_total or 0,
        "findings_critical": scan_row.findings_critical or 0,
    }


@router.get("/version")
async def version_check(current_user: User = Depends(get_current_user)):
    """Return current version and latest GitHub release. Authenticated: the
    exact running version is useful reconnaissance for an attacker."""
    import httpx
    current = settings.app_version
    latest = None
    release_url = None

    # Cache in Redis to avoid hammering GitHub API
    try:
        from scanr.db.redis import get_redis
        r = get_redis()
        cached = await r.get("scanr:version:latest")
        if cached:
            import json
            cached_data = json.loads(cached)
            latest = cached_data.get("tag_name", "").lstrip("v")
            _cached_url = cached_data.get("html_url", "")
            release_url = _cached_url if _cached_url.startswith("https://github.com/") else None
    except Exception:
        pass

    if not latest:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    "https://api.github.com/repos/T3rr0or/ScanR/releases/latest",
                    headers={"Accept": "application/vnd.github+json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    latest = data.get("tag_name", "").lstrip("v")
                    _raw_url = data.get("html_url", "")
                    release_url = _raw_url if _raw_url.startswith("https://github.com/") else None
                    # Cache 1 hour
                    import json
                    from scanr.db.redis import get_redis as _gred
                    _rc = _gred()
                    await _rc.setex("scanr:version:latest", 3600, json.dumps(data))
        except Exception as exc:
            logger.debug("Version check failed: %s", exc)

    update_available = False
    if latest and current:
        try:
            from packaging.version import Version
            update_available = Version(latest) > Version(current)
        except Exception:
            update_available = latest != current

    return {
        "current": current,
        "latest": latest,
        "update_available": update_available,
        "release_url": release_url,
        "self_update_enabled": settings.self_update_enabled,
    }


@router.get("/update/status")
async def update_status(
    current_user: User = Depends(require_admin_scope("system:manage")),
):
    return await _get_update_status()


@router.delete("/update/status")
async def reset_update_status(
    current_user: User = Depends(require_admin_scope("system:manage")),
):
    """Clear terminal status without allowing a second live update."""
    from scanr.db.redis import get_redis
    if await get_redis().exists(UPDATE_LOCK_KEY):
        raise HTTPException(status_code=409, detail="An update is still active")
    await _set_update_status(_default_update_status())
    return {"state": "idle"}


@router.post("/update")
async def start_update(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_session_admin),
):
    if not settings.self_update_enabled:
        raise HTTPException(
            status_code=403,
            detail="Self-update is disabled. Set SELF_UPDATE_ENABLED=true and configure SELF_UPDATE_WORKDIR/SELF_UPDATE_COMMAND.",
        )

    from scanr.db.redis import get_redis
    lock_token = uuid.uuid4().hex
    try:
        acquired = await get_redis().set(
            UPDATE_LOCK_KEY, lock_token, nx=True, ex=UPDATE_LOCK_TTL,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Update coordination unavailable") from exc
    if not acquired:
        raise HTTPException(status_code=409, detail="Update already queued or running")

    await _set_update_status({
        "enabled": True,
        "state": "queued",
        "api_instance": _API_INSTANCE,
        "started_at": _utc_now(),
        "finished_at": None,
        "exit_code": None,
        "message": "Update queued",
        "log": "",
    })
    background_tasks.add_task(_run_self_update, lock_token)
    await asyncio.sleep(0)
    return await _get_update_status()


@router.get("/cve-status")
async def cve_status(current_user: User = Depends(get_current_user)):
    from scanr.plugins.cve import epss
    from scanr.plugins.cve.nvd_loader import get_last_updated, get_kev_cve_ids, DB_PATH
    epss_status = epss.status()
    return {
        "last_updated": get_last_updated(),
        "nvd_db_exists": DB_PATH.exists(),
        "kev_count": len(get_kev_cve_ids()),
        "epss_count": epss_status["count"],
        "epss_score_date": epss_status["score_date"],
    }


@router.post("/cve-refresh")
async def cve_refresh(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin_scope("system:manage")),
):
    """Trigger a background refresh of NVD, CISA KEV and EPSS, then re-rank findings."""
    async def _refresh():
        from scanr.core.priority_service import rescore
        from scanr.db.session import AsyncSessionLocal
        from scanr.plugins.cve import kev_cache
        from scanr.plugins.cve.nvd_loader import download_feeds
        logger.info("CVE feed refresh started by admin")
        await asyncio.to_thread(download_feeds)
        kev_cache.invalidate()
        async with AsyncSessionLocal() as db:
            scored = await rescore(db)
        logger.info("CVE feed refresh complete; re-ranked %d findings", scored)

    background_tasks.add_task(_refresh)
    return {"status": "refresh_started"}
