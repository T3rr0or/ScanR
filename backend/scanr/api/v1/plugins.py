from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user, require_admin
from scanr.models import Plugin
from scanr.models.user import User
from scanr.schemas import PluginRead, PluginUpdate

router = APIRouter(prefix="/plugins", tags=["plugins"])


@router.get("", response_model=list[PluginRead])
async def list_plugins(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Plugin).order_by(Plugin.category, Plugin.name))
    return result.scalars().all()


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
