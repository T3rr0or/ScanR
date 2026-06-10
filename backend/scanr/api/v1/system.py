from __future__ import annotations

import logging
import asyncio
import json
import os
import shlex
import subprocess
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import Integer, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.db import get_db
from scanr.deps import get_current_user, require_admin
from scanr.models import Scan, ScanStatus
from scanr.models.user import User

router = APIRouter(prefix="/system", tags=["system"])
logger = logging.getLogger(__name__)
settings = get_settings()
UPDATE_STATUS_KEY = "scanr:update:status"


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
            # Stale "running" guard: if running for >15 min the process died
            if data.get("state") in ("running", "queued") and data.get("started_at"):
                from datetime import datetime, timezone, timedelta
                try:
                    started = datetime.fromisoformat(data["started_at"])
                    if datetime.now(timezone.utc) - started > timedelta(minutes=15):
                        data["state"] = "failed"
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


async def _run_self_update() -> None:
    status = {
        "enabled": settings.self_update_enabled,
        "state": "running",
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
            "SCANR_VERSION": os.environ.get("SCANR_VERSION", "latest"),
        }
        commands = _split_update_command(settings.self_update_command)

        for i, argv in enumerate(commands):
            is_last = i == len(commands) - 1
            logs.append(f"$ {' '.join(shlex.quote(x) for x in argv)}")

            if is_last and _is_restart_cmd(argv):
                # Persist "succeeded" before firing the restart — the restart
                # will kill this container so we cannot write status after it.
                status.update({
                    "state": "succeeded",
                    "finished_at": _utc_now(),
                    "exit_code": 0,
                    "message": "Images pulled. Restarting services — ScanR will be back in a few seconds.",
                    "log": "\n".join(logs)[-12000:],
                })
                await _set_update_status(status)
                subprocess.Popen(
                    argv, cwd=workdir, env=env,
                    start_new_session=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                return

            proc = subprocess.run(
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


@router.get("/health")
async def health():
    return {"status": "ok", "service": "scanr"}


@router.get("/stats")
async def stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    uid = current_user.id

    # Scan counts in one query
    scan_row = (await db.execute(
        select(
            func.count(Scan.id).label("total"),
            func.sum(cast(Scan.status == ScanStatus.running, Integer)).label("running"),
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
        "hosts_total": scan_row.hosts_total or 0,
        "findings_total": scan_row.findings_total or 0,
        "findings_critical": scan_row.findings_critical or 0,
    }


@router.get("/version")
async def version_check():
    """Return current version and latest GitHub release."""
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
async def update_status(current_user: User = Depends(require_admin)):
    return await _get_update_status()


@router.delete("/update/status")
async def reset_update_status(current_user: User = Depends(require_admin)):
    """Clear stale update status back to idle."""
    await _set_update_status(_default_update_status())
    return {"state": "idle"}


@router.post("/update")
async def start_update(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
):
    if not settings.self_update_enabled:
        raise HTTPException(
            status_code=403,
            detail="Self-update is disabled. Set SELF_UPDATE_ENABLED=true and configure SELF_UPDATE_WORKDIR/SELF_UPDATE_COMMAND.",
        )

    status = await _get_update_status()
    if status.get("state") == "running":
        raise HTTPException(status_code=409, detail="Update already running")

    await _set_update_status({
        "enabled": True,
        "state": "queued",
        "started_at": _utc_now(),
        "finished_at": None,
        "exit_code": None,
        "message": "Update queued",
        "log": "",
    })
    background_tasks.add_task(_run_self_update)
    await asyncio.sleep(0)
    return await _get_update_status()


@router.get("/cve-status")
async def cve_status(current_user: User = Depends(get_current_user)):
    from scanr.plugins.cve.nvd_loader import get_last_updated, get_kev_cve_ids, DB_PATH
    return {
        "last_updated": get_last_updated(),
        "nvd_db_exists": DB_PATH.exists(),
        "kev_count": len(get_kev_cve_ids()),
    }


@router.post("/cve-refresh")
async def cve_refresh(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
):
    """Trigger a background refresh of NVD feeds and CISA KEV catalog."""
    def _refresh():
        from scanr.plugins.cve.nvd_loader import download_feeds
        logger.info("CVE feed refresh started by admin")
        download_feeds()
        logger.info("CVE feed refresh complete")

    background_tasks.add_task(_refresh)
    return {"status": "refresh_started"}
