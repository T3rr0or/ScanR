from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models import Finding, Host, Scan, ScanStatus
from scanr.models.user import User

router = APIRouter(prefix="/system", tags=["system"])


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
