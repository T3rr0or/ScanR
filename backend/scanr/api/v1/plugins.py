from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user, require_admin
from scanr.models import Plugin, PluginRun, Scan
from scanr.models.user import User
from scanr.schemas import PluginHealthRead, PluginRead, PluginRunRead, PluginUpdate

router = APIRouter(prefix="/plugins", tags=["plugins"])


@router.get("", response_model=list[PluginRead])
async def list_plugins(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Plugin).order_by(Plugin.category, Plugin.name))
    return result.scalars().all()


@router.get("/runs", response_model=list[PluginRunRead])
async def list_plugin_runs(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan_result = await db.execute(
        select(Scan.id).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    result = await db.execute(
        select(PluginRun)
        .where(PluginRun.scan_id == scan_id)
        .order_by(PluginRun.created_at.desc())
    )
    return result.scalars().all()


@router.get("/health", response_model=list[PluginHealthRead])
async def plugin_health(
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = (
        select(
            PluginRun.plugin_id.label("plugin_id"),
            func.count(PluginRun.id).label("total_runs"),
            func.sum(case((PluginRun.status == "success", 1), else_=0)).label("success_count"),
            func.sum(case((PluginRun.status == "timeout", 1), else_=0)).label("timeout_count"),
            func.sum(case((PluginRun.status == "error", 1), else_=0)).label("error_count"),
            func.coalesce(func.sum(PluginRun.findings_count), 0).label("findings_count"),
            func.coalesce(func.avg(PluginRun.duration_ms), 0).label("avg_duration_ms"),
            func.coalesce(func.max(PluginRun.duration_ms), 0).label("max_duration_ms"),
        )
        .join(Scan, Scan.id == PluginRun.scan_id)
        .where(Scan.user_id == current_user.id)
    )
    if scan_id:
        q = q.where(PluginRun.scan_id == scan_id)
    q = q.group_by(PluginRun.plugin_id).order_by(
        func.sum(case((PluginRun.status == "timeout", 1), else_=0)).desc(),
        func.sum(case((PluginRun.status == "error", 1), else_=0)).desc(),
        PluginRun.plugin_id,
    )
    result = await db.execute(q)
    return [
        PluginHealthRead(
            plugin_id=row.plugin_id,
            total_runs=int(row.total_runs or 0),
            success_count=int(row.success_count or 0),
            timeout_count=int(row.timeout_count or 0),
            error_count=int(row.error_count or 0),
            findings_count=int(row.findings_count or 0),
            avg_duration_ms=int(row.avg_duration_ms or 0),
            max_duration_ms=int(row.max_duration_ms or 0),
        )
        for row in result.all()
    ]


@router.get("/{plugin_id}", response_model=PluginRead)
async def get_plugin(
    plugin_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Plugin).where(Plugin.id == plugin_id))
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return plugin


@router.patch("/{plugin_id}", response_model=PluginRead)
async def update_plugin(
    plugin_id: str,
    body: PluginUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    result = await db.execute(select(Plugin).where(Plugin.id == plugin_id))
    plugin = result.scalar_one_or_none()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    if body.enabled is not None:
        plugin.enabled = body.enabled
    if body.config_json is not None:
        plugin.config_json = body.config_json

    await db.commit()
    await db.refresh(plugin)
    return plugin
