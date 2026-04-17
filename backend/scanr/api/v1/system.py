from __future__ import annotations

import logging
from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.db import get_db
from scanr.deps import get_current_user, require_admin
from scanr.models import Finding, Host, Scan, ScanStatus
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
    scans_total = (await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == uid)
    )).scalar()
    scans_running = (await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == uid, Scan.status == ScanStatus.running)
    )).scalar()
    hosts_total = (await db.execute(
        select(func.count(Host.id)).join(Scan, Host.scan_id == Scan.id).where(Scan.user_id == uid)
    )).scalar()
    findings_total = (await db.execute(
        select(func.count(Finding.id)).join(Scan, Finding.scan_id == Scan.id).where(Scan.user_id == uid)
    )).scalar()
    findings_critical = (await db.execute(
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.user_id == uid, Finding.severity == "critical", Finding.false_positive == False)
    )).scalar()

    return {
        "scans_total": scans_total,
        "scans_running": scans_running,
        "hosts_total": hosts_total,
        "findings_total": findings_total,
        "findings_critical": findings_critical,
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
            release_url = cached_data.get("html_url")
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
                    release_url = data.get("html_url")
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
