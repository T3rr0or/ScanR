from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.ai import settings_store as store
from scanr.ai.assist.summary import summarize_findings
from scanr.ai.llm.factory import (
    SUPPORTED_PROVIDERS,
    AIProviderError,
    build_provider,
)
from scanr.config import get_settings
from scanr.core.limiter import limiter
from scanr.db import get_db
from scanr.deps import get_current_user, require_admin, require_scope
from scanr.models import Finding, Host, Scan
from scanr.models.user import User
from scanr.utils.exceptions import VaultError

router = APIRouter(prefix="/ai", tags=["ai"])
logger = logging.getLogger(__name__)


def _check_provider(provider: str) -> None:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider {provider!r}. Supported: {', '.join(SUPPORTED_PROVIDERS)}.",
        )


class SummaryRequest(BaseModel):
    provider: str | None = None
    model: str | None = None
    include_false_positives: bool = False


class ApiKeyBody(BaseModel):
    api_key: str = Field(min_length=8, max_length=512)


class AIConfigBody(BaseModel):
    provider: str | None = None
    model: str | None = Field(default=None, max_length=128)


@router.get("/status")
async def ai_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Report which providers have a key configured (and from where) so the UI
    can gate AI features. Never returns the keys themselves."""
    sources = await store.key_sources(db)
    return {
        "enabled": any(v is not None for v in sources.values()),
        "default_provider": await store.get_default_provider(db),
        "default_model": (await store.get_default_model(db)) or None,
        "providers": list(SUPPORTED_PROVIDERS),
        # provider -> "stored" | "env" | null
        "key_sources": sources,
        "configured": {p: (s is not None) for p, s in sources.items()},
    }


@router.put("/keys/{provider}", status_code=204)
async def set_api_key(
    provider: str,
    body: ApiKeyBody,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Store an encrypted provider API key entered from the web app (admin only)."""
    _check_provider(provider)
    try:
        await store.set_api_key(db, provider, body.api_key.strip())
    except VaultError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot store key — VAULT_KEY is required for encrypted settings: {exc}",
        )
    logger.info("AI API key for %s set by %s", provider, current_user.email)


@router.delete("/keys/{provider}", status_code=204)
async def delete_api_key(
    provider: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Remove a stored provider API key (admin only). Env keys are unaffected."""
    _check_provider(provider)
    await store.clear_api_key(db, provider)
    logger.info("AI API key for %s cleared by %s", provider, current_user.email)


@router.put("/config", status_code=204)
async def set_config(
    body: AIConfigBody,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Set the default AI provider/model (admin only)."""
    if body.provider is not None:
        _check_provider(body.provider)
    await store.set_defaults(db, body.provider, body.model)


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

    own = await db.execute(select(Scan.id).where(Scan.id == scan_id, Scan.user_id == current_user.id))
    if own.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    provider_name = body.provider or await store.get_default_provider(db)
    model = body.model or (await store.get_default_model(db)) or None
    if provider_name not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider {provider_name!r}.")
    api_key = await store.resolve_api_key(db, provider_name)

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
        provider = build_provider(provider_name, model, api_key=api_key)
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
