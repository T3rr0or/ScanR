from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Report, Scan
from scanr.models.base import new_uuid
from scanr.models.user import User
from scanr.schemas import ReportCreate, ReportRead

router = APIRouter(prefix="/reports", tags=["reports"])


async def _get_own_report(report_id: str, user_id: str, db: AsyncSession) -> Report:
    result = await db.execute(
        select(Report)
        .join(Scan, Report.scan_id == Scan.id)
        .where(Report.id == report_id, Scan.user_id == user_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("", response_model=list[ReportRead])
async def list_reports(
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("reports:read")),
):
    q = (
        select(Report)
        .join(Scan, Report.scan_id == Scan.id)
        .where(Scan.user_id == current_user.id)
        .order_by(Report.created_at.desc())
    )
    if scan_id:
        q = q.where(Report.scan_id == scan_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=ReportRead, status_code=201)
async def create_report(
    body: ReportCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("reports:export")),
):
    result = await db.execute(
        select(Scan).where(Scan.id == body.scan_id, Scan.user_id == current_user.id)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    report = Report(
        id=new_uuid(),
        scan_id=body.scan_id,
        format=body.format,
        status="pending",
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    from scanr.tasks.report_tasks import generate_report_task
    generate_report_task.delay(report.id)

    return report


@router.get("/{report_id}", response_model=ReportRead)
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("reports:read")),
):
    return await _get_own_report(report_id, current_user.id, db)


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("reports:export")),
):
    report = await _get_own_report(report_id, current_user.id, db)
    if report.status != "completed" or not report.file_path:
        raise HTTPException(status_code=400, detail="Report not ready")
    path = Path(report.file_path).resolve()
    reports_dir = Path(get_settings().reports_dir).resolve()
    if not str(path).startswith(str(reports_dir) + "/"):
        raise HTTPException(status_code=403, detail="Invalid report path")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file missing")
    return FileResponse(path, filename=path.name)
