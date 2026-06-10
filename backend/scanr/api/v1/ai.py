from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.ai.assist.summary import summarize_findings
from scanr.ai.llm.factory import (
    SUPPORTED_PROVIDERS,
    AIProviderError,
    build_provider,
)
from scanr.config import get_settings
from scanr.core.limiter import limiter
from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Finding, Host, Scan
from scanr.models.user import User

router = APIRouter(prefix="/ai", tags=["ai"])
logger = logging.getLogger(__name__)


class SummaryRequest(BaseModel):
    provider: str | None = None
    model: str | None = None
    include_false_positives: bool = False


@router.get("/status")
async def ai_status(current_user: User = Depends(require_scope("findings:read"))):
    """Report which providers have a key configured, for the UI to gate AI features."""
    settings = get_settings()
    configured = {
        "anthropic": bool(settings.anthropic_api_key),
        "openai": bool(settings.openai_api_key),
        "deepseek": bool(settings.deepseek_api_key),
    }
    return {
        "enabled": any(configured.values()),
        "default_provider": settings.ai_provider,
        "default_model": settings.ai_model or None,
        "providers": SUPPORTED_PROVIDERS,
        "configured": configured,
    }


@router.post("/scans/{scan_id}/summary")
@limiter.limit("10/minute")
async def summarize_scan(
    request: Request,
    scan_id: str,
    body: SummaryRequest | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    """Generate an AI narrative summary of a scan's findings (read-only, assist mode)."""
    body = body or SummaryRequest()

    # Ownership check
    own = await db.execute(select(Scan.id).where(Scan.id == scan_id, Scan.user_id == current_user.id))
    if own.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    q = (
        select(Finding, Host.ip.label("host_ip"))
        .outerjoin(Host, Finding.host_id == Host.id)
        .where(Finding.scan_id == scan_id)
    )
    if not body.include_false_positives:
        q = q.where(Finding.false_positive == False)  # noqa: E712
    rows = (await db.execute(q)).all()

    findings = [
        {
            "severity": f.severity,
            "title": f.title,
            "host_ip": ip,
            "host_id": f.host_id,
            "port_number": f.port_number,
            "description": f.description,
            "cvss_score": f.cvss_score,
        }
        for f, ip in rows
    ]

    try:
        provider = build_provider(body.provider, body.model)
    except AIProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    settings = get_settings()
    try:
        result = await summarize_findings(provider, findings, max_tokens=settings.ai_max_tokens)
    except RuntimeError as exc:  # SDK not installed
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:  # provider/network error
        logger.warning("AI summary failed for scan %s: %s", scan_id, exc)
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")

    return {
        "scan_id": scan_id,
        "summary": result.text,
        "provider": result.provider,
        "model": result.model,
        "finding_count": result.finding_count,
        "usage": {
            "input_tokens": result.usage.input_tokens,
            "output_tokens": result.usage.output_tokens,
            "cached_input_tokens": result.usage.cached_input_tokens,
        },
    }
