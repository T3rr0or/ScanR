from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models import Screenshot
from scanr.models.scan import Scan
from scanr.models.user import User

router = APIRouter(prefix="/screenshots", tags=["screenshots"])


class ScreenshotRead(BaseModel):
    id: str
    scan_id: str
    host_id: str
    port_number: int
    url: str
    file_path: str | None
    title: str | None
    status_code: int | None
    content_type: str | None
    error: str | None

    model_config = {"from_attributes": True}

    @field_validator("file_path", mode="before")
    @classmethod
    def _basename_only(cls, v: object) -> object:
        # Never expose absolute server filesystem paths to API clients —
        # return only the file name. Images are fetched via /{id}/image.
        if isinstance(v, str) and v:
            return Path(v).name
        return v


@router.get("", response_model=list[ScreenshotRead])
async def list_screenshots(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Screenshot)
        .join(Scan, Screenshot.scan_id == Scan.id)
        .where(
            Screenshot.scan_id == scan_id,
            Screenshot.file_path.isnot(None),
            Scan.user_id == current_user.id,
        )
        .order_by(Screenshot.created_at)
    )
    return result.scalars().all()


@router.get("/{screenshot_id}/image")
async def get_screenshot_image(
    screenshot_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Screenshot)
        .join(Scan, Screenshot.scan_id == Scan.id)
        .where(
            Screenshot.id == screenshot_id,
            Scan.user_id == current_user.id,
        )
    )
    shot = result.scalar_one_or_none()
    if not shot:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    if not shot.file_path:
        raise HTTPException(status_code=404, detail="No image captured")
    from scanr.config import get_settings

    path = Path(shot.file_path).resolve()
    reports_dir = Path(get_settings().reports_dir).resolve()
    # Defence in depth: only serve files from under the reports directory.
    if not path.is_relative_to(reports_dir):
        raise HTTPException(status_code=403, detail="Invalid screenshot path")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Image file missing")
    return FileResponse(path, media_type="image/png")
