"""Word report templates: the built-in default and uploaded house styles.

Everyone who can read reports can list and download templates. Uploading and
deleting is for administrators: a template's text appears in every report.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.db import get_db
from scanr.deps import require_admin_scope, require_scope
from scanr.models.base import new_uuid
from scanr.models.report_template import ReportTemplate
from scanr.models.user import User
from scanr.reporting import docx_renderer

router = APIRouter(prefix="/report-templates", tags=["reports"])
_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


class ReportTemplateRead(BaseModel):
    id: str
    name: str
    description: str | None
    filename: str
    size: int
    uploaded_by: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PlaceholderHelp(BaseModel):
    placeholders: dict[str, str]


@router.get("", response_model=list[ReportTemplateRead])
async def list_templates(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_scope("reports:read")),
):
    return (await db.execute(select(ReportTemplate).order_by(ReportTemplate.name))).scalars().all()


@router.get("/placeholders", response_model=PlaceholderHelp)
async def placeholders(_user: User = Depends(require_scope("reports:read"))):
    return PlaceholderHelp(placeholders=docx_renderer.PLACEHOLDERS)


@router.get("/default/download")
async def download_default(_user: User = Depends(require_scope("reports:read"))):
    """The built-in template, to brand and upload back."""
    return Response(
        docx_renderer.build_default_template(),
        media_type=_DOCX,
        headers={"Content-Disposition": 'attachment; filename="scanr-report-template.docx"'},
    )


@router.get("/{template_id}/download")
async def download_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_scope("reports:read")),
):
    template = await db.get(ReportTemplate, template_id)
    path = docx_renderer.template_dir() / f"{template_id}.docx"
    if template is None or not path.exists():
        raise HTTPException(status_code=404, detail="Template not found")
    return FileResponse(path, media_type=_DOCX, filename=template.filename)


@router.post("", response_model=ReportTemplateRead, status_code=status.HTTP_201_CREATED)
async def upload_template(
    file: UploadFile = File(...),
    name: str = Form(..., min_length=1, max_length=255),
    description: str = Form("", max_length=2000),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin_scope("system:manage")),
):
    data = await file.read(10 * 1024 * 1024 + 1)
    try:
        docx_renderer.validate_template(data)
    except docx_renderer.TemplateError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if (await db.execute(select(ReportTemplate.id).where(func.lower(ReportTemplate.name) == name.strip().lower()))).first():
        raise HTTPException(status_code=409, detail="A template with this name already exists")
    template = ReportTemplate(
        id=new_uuid(), name=name.strip(), description=description.strip() or None,
        filename=docx_renderer.safe_template_name(file.filename or "template.docx"),
        size=len(data), uploaded_by=admin.email,
    )
    directory = docx_renderer.template_dir()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{template.id}.docx").write_bytes(data)
    db.add(template)
    await db.commit()
    await db.refresh(template)
    return template


@router.delete("/{template_id}", status_code=204)
async def delete_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_scope("system:manage")),
):
    template = await db.get(ReportTemplate, template_id)
    if template is None:
        raise HTTPException(status_code=404, detail="Template not found")
    await db.delete(template)
    await db.commit()
    (docx_renderer.template_dir() / f"{template_id}.docx").unlink(missing_ok=True)
