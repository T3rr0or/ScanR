from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.ai import settings_store as store
from scanr.ai.assist.false_positive import test_false_positives
from scanr.ai.assist.report import generate_report_narrative
from scanr.ai.assist.summary import summarize_findings
from scanr.ai.llm.factory import (
    SUPPORTED_PROVIDERS,
    AIProviderError,
    build_provider,
    default_model,
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
    provider: str


class ModelBody(BaseModel):
    # empty string clears the override (revert to the provider's built-in default)
    model: str = Field(default="", max_length=128)


@router.get("/status")
async def ai_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Report which providers have a key configured (and from where) so the UI
    can gate AI features. Never returns the keys themselves."""
    sources = await store.key_sources(db)
    overrides = await store.models(db)
    return {
        "enabled": any(v is not None for v in sources.values()),
        "default_provider": await store.get_default_provider(db),
        "providers": list(SUPPORTED_PROVIDERS),
        # provider -> "stored" | "env" | null
        "key_sources": sources,
        "configured": {p: (s is not None) for p, s in sources.items()},
        # per provider: the operator's model override (or null), and the
        # effective model (override, else the built-in default)
        "model_overrides": overrides,
        "default_models": {p: default_model(p) for p in SUPPORTED_PROVIDERS},
        "effective_models": {p: (overrides[p] or default_model(p)) for p in SUPPORTED_PROVIDERS},
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
    """Set the default AI provider (admin only)."""
    _check_provider(body.provider)
    await store.set_default_provider(db, body.provider)


@router.put("/models/{provider}", status_code=204)
async def set_model(
    provider: str,
    body: ModelBody,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Set (or clear, with an empty model) the model used for a provider (admin)."""
    _check_provider(provider)
    await store.set_model(db, provider, body.model)


async def _own_scan(db: AsyncSession, scan_id: str, user_id: str) -> Scan:
    res = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id))
    scan = res.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


async def _build_provider(db: AsyncSession, provider: str | None, model: str | None):
    """Resolve provider/model/key and construct the provider, or raise HTTPException."""
    provider_name = provider or await store.get_default_provider(db)
    if provider_name not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider {provider_name!r}.")
    chosen_model = model or (await store.get_model(db, provider_name)) or None
    api_key = await store.resolve_api_key(db, provider_name)
    try:
        return build_provider(provider_name, chosen_model, api_key=api_key)
    except AIProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


async def _load_findings(db: AsyncSession, scan_id: str, *, include_false_positives: bool) -> list[dict]:
    q = (
        select(Finding, Host.ip.label("host_ip"))
        .outerjoin(Host, Finding.host_id == Host.id)
        .where(Finding.scan_id == scan_id)
    )
    if not include_false_positives:
        q = q.where(Finding.false_positive == False)  # noqa: E712
    rows = (await db.execute(q)).all()
    return [
        {
            "id": f.id,
            "severity": f.severity,
            "title": f.title,
            "host_ip": ip,
            "host_id": f.host_id,
            "port_number": f.port_number,
            "description": f.description,
            "evidence": f.evidence,
            "cvss_score": f.cvss_score,
            "false_positive": f.false_positive,
        }
        for f, ip in rows
    ]


def _usage_dict(usage) -> dict:
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cached_input_tokens": usage.cached_input_tokens,
    }


async def _run_assist(coro):
    """Map provider/SDK errors from an assist coroutine to HTTP responses."""
    try:
        return await coro
    except RuntimeError as exc:  # SDK not installed
        raise HTTPException(status_code=503, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:  # provider/network error
        logger.warning("AI assist call failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"AI provider error: {exc}")


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
    await _own_scan(db, scan_id, current_user.id)
    provider = await _build_provider(db, body.provider, body.model)
    findings = await _load_findings(db, scan_id, include_false_positives=body.include_false_positives)
    result = await _run_assist(
        summarize_findings(provider, findings, max_tokens=get_settings().ai_max_tokens)
    )
    return {
        "scan_id": scan_id,
        "summary": result.text,
        "provider": result.provider,
        "model": result.model,
        "finding_count": result.finding_count,
        "usage": _usage_dict(result.usage),
    }


@router.post("/scans/{scan_id}/report")
@limiter.limit("10/minute")
async def report_narrative(
    request: Request,
    scan_id: str,
    body: SummaryRequest | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    """Generate a structured engagement-report narrative (read-only, assist mode)."""
    body = body or SummaryRequest()
    scan = await _own_scan(db, scan_id, current_user.id)
    provider = await _build_provider(db, body.provider, body.model)
    findings = await _load_findings(db, scan_id, include_false_positives=body.include_false_positives)
    result = await _run_assist(
        generate_report_narrative(
            provider, findings, scan_name=scan.name, max_tokens=max(get_settings().ai_max_tokens, 3072)
        )
    )
    return {
        "scan_id": scan_id,
        "report": result.text,
        "provider": result.provider,
        "model": result.model,
        "finding_count": result.finding_count,
        "usage": _usage_dict(result.usage),
    }


@router.post("/scans/{scan_id}/false-positives")
@limiter.limit("10/minute")
async def false_positives(
    request: Request,
    scan_id: str,
    body: SummaryRequest | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    """Have the model flag findings likely to be false positives (advisory only)."""
    body = body or SummaryRequest()
    await _own_scan(db, scan_id, current_user.id)
    provider = await _build_provider(db, body.provider, body.model)
    findings = await _load_findings(db, scan_id, include_false_positives=False)
    result = await _run_assist(
        test_false_positives(provider, findings, max_tokens=get_settings().ai_max_tokens)
    )
    return {
        "scan_id": scan_id,
        "items": result.items,
        "assessed_count": result.assessed_count,
        "flagged_count": len(result.items),
        "provider": result.provider,
        "model": result.model,
        "usage": _usage_dict(result.usage),
    }
