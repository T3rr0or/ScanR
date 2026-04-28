from __future__ import annotations

import logging
from fastapi import APIRouter, BackgroundTasks, Depends
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
        import redis
        r = redis.from_url(settings.redis_url, decode_responses=True)
        cached = r.get("scanr:version:latest")
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
                    import redis, json
                    r = redis.from_url(settings.redis_url, decode_responses=True)
                    r.setex("scanr:version:latest", 3600, json.dumps(data))
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
    }


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
