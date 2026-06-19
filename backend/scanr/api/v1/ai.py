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
from scanr.ai.llm.models import list_models as fetch_models
from scanr.config import get_settings
from scanr.core.limiter import limiter
from scanr.db import get_db
from scanr.deps import get_current_user, require_admin, require_scope
from scanr.models import AiAgentRun, Finding, Host, Scan
from scanr.models.base import new_uuid
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


class SaveResultBody(BaseModel):
    type: str = Field(pattern="^(summary|report|false_positives)$")
    content: dict  # the full API response to save


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


@router.get("/models/available/{provider}")
async def list_provider_models(
    provider: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Fetch available models from the provider's API (cached for 5 min)."""
    _check_provider(provider)
    api_key = await store.resolve_api_key(db, provider)
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail=f"No API key configured for provider {provider!r}. Add one first.",
        )
    try:
        models = await fetch_models(provider, api_key)
        return {"provider": provider, "models": models}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch models: {exc}")


async def _save_result(
    db: AsyncSession,
    scan_id: str,
    result_type: str,
    provider: str,
    model: str,
    content: dict,
    usage: dict | None,
) -> str:
    """Persist an AI result to the database."""
    from scanr.models.ai_result import AiResult
    from scanr.models.base import new_uuid
    import json as _json

    result = AiResult(
        id=new_uuid(),
        scan_id=scan_id,
        type=result_type,
        provider=provider,
        model=model,
        content=_json.dumps(content),
        token_usage=_json.dumps(usage) if usage else None,
    )
    db.add(result)
    await db.commit()
    return result.id


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
        summarize_findings(provider, findings, max_tokens=max(get_settings().ai_max_tokens, 3072))
    )
    response = {
        "scan_id": scan_id,
        "summary": result.text,
        "provider": result.provider,
        "model": result.model,
        "finding_count": result.finding_count,
        "truncated": result.truncated,
        "usage": _usage_dict(result.usage),
    }
    try:
        response["saved_id"] = await _save_result(
            db,
            scan_id,
            "summary",
            result.provider,
            result.model,
            {"text": result.text},
            _usage_dict(result.usage),
        )
    except Exception:
        logger.warning("Failed to persist summary result for scan %s", scan_id)
    return response


@router.get("/scans/{scan_id}/results")
async def list_results(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    """List saved AI results for a scan."""
    await _own_scan(db, scan_id, current_user.id)
    from scanr.models.ai_result import AiResult
    import json as _json

    rows = (
        (await db.execute(select(AiResult).where(AiResult.scan_id == scan_id).order_by(AiResult.created_at.desc())))
        .scalars()
        .all()
    )
    return [
        {
            "id": r.id,
            "type": r.type,
            "provider": r.provider,
            "model": r.model,
            "content": _json.loads(r.content) if isinstance(r.content, str) else r.content,
            "token_usage": _json.loads(r.token_usage) if r.token_usage else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


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
    response = {
        "scan_id": scan_id,
        "report": result.text,
        "provider": result.provider,
        "model": result.model,
        "finding_count": result.finding_count,
        "truncated": result.truncated,
        "usage": _usage_dict(result.usage),
    }
    try:
        response["saved_id"] = await _save_result(
            db,
            scan_id,
            "report",
            result.provider,
            result.model,
            {"text": result.text},
            _usage_dict(result.usage),
        )
    except Exception:
        logger.warning("Failed to persist report result for scan %s", scan_id)
    return response


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
    result = await _run_assist(test_false_positives(provider, findings, max_tokens=get_settings().ai_max_tokens))
    response = {
        "scan_id": scan_id,
        "items": result.items,
        "methodology": result.methodology,
        "assessed_count": result.assessed_count,
        "flagged_count": len(result.items),
        "truncated": result.truncated,
        "provider": result.provider,
        "model": result.model,
        "usage": _usage_dict(result.usage),
    }
    try:
        response["saved_id"] = await _save_result(
            db,
            scan_id,
            "false_positives",
            result.provider,
            result.model,
            {"items": result.items, "methodology": result.methodology},
            _usage_dict(result.usage),
        )
    except Exception:
        logger.warning("Failed to persist FP result for scan %s", scan_id)
    return response


# ── guided / autonomous agent ───────────────────────────────────────────────

class AgentRunRequest(BaseModel):
    mode: str = Field(default="guided", pattern="^(guided|autonomous)$")
    objective: str = Field(default="", max_length=2000)
    provider: str | None = None
    model: str | None = None
    # Aggressive opt-ins — each gated; only take effect with aggressive=True.
    aggressive: bool = False
    allow_privilege_escalation: bool = False
    allow_exploitation: bool = False
    allow_command_exec: bool = False

    def aggressive_requested(self) -> bool:
        return (
            self.aggressive
            or self.allow_privilege_escalation
            or self.allow_exploitation
            or self.allow_command_exec
        )


def _agent_run_dict(run: AiAgentRun) -> dict:
    import json as _json
    return {
        "id": run.id,
        "scan_id": run.scan_id,
        "status": run.status,
        "mode": run.mode,
        "objective": run.objective,
        "provider": run.provider,
        "model": run.model,
        "stop_reason": run.stop_reason,
        "capabilities": _json.loads(run.capabilities) if run.capabilities else None,
        "final_text": run.final_text,
        "actions": _json.loads(run.actions) if run.actions else [],
        "token_usage": _json.loads(run.token_usage) if run.token_usage else None,
        "error": run.error,
        "pending_approval": _json.loads(run.pending_approval) if run.pending_approval else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


@router.post("/scans/{scan_id}/agent", status_code=202)
@limiter.limit("5/minute")
async def launch_agent(
    request: Request,
    scan_id: str,
    body: AgentRunRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    """Launch a guided/autonomous AI agent run against a completed scan."""
    await _own_scan(db, scan_id, current_user.id)

    # Aggressive capabilities (exploitation / privilege escalation) are admin-only
    # and unlock active, potentially-destructive actions — require an admin.
    if body.aggressive_requested() and getattr(current_user, "role", None) != "admin":
        raise HTTPException(
            status_code=403,
            detail="Aggressive capabilities require an admin user.",
        )

    # Validate provider + key up front so the user gets an immediate, clear error
    # instead of a failed background run.
    provider_name = body.provider or await store.get_default_provider(db)
    if provider_name not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider {provider_name!r}.")
    if not await store.resolve_api_key(db, provider_name):
        raise HTTPException(
            status_code=400,
            detail=f"No API key configured for provider {provider_name!r}. Add one in Settings → AI.",
        )

    objective = body.objective.strip() or (
        "Investigate this scan's findings and hosts. Identify the most serious, "
        "exploitable issues, corroborate them with the available tools, and write "
        "a prioritized assessment with concrete next steps."
    )
    # If any aggressive sub-capability is requested, aggressive is implied on.
    import json as _json
    caps = {
        "aggressive": body.aggressive_requested(),
        "allow_privilege_escalation": body.allow_privilege_escalation,
        "allow_exploitation": body.allow_exploitation,
        "allow_command_exec": body.allow_command_exec,
    }
    run = AiAgentRun(
        id=new_uuid(),
        scan_id=scan_id,
        status="queued",
        mode=body.mode,
        objective=objective,
        provider=provider_name,
        model=body.model,
        capabilities=_json.dumps(caps) if caps["aggressive"] else None,
    )
    db.add(run)
    await db.commit()

    from scanr.tasks.agent_tasks import run_ai_agent_task
    run_ai_agent_task.delay(run.id)
    return _agent_run_dict(run)


@router.get("/scans/{scan_id}/agent/runs")
async def list_agent_runs(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    """List AI agent runs for a scan, newest first."""
    await _own_scan(db, scan_id, current_user.id)
    rows = (
        (await db.execute(
            select(AiAgentRun).where(AiAgentRun.scan_id == scan_id).order_by(AiAgentRun.created_at.desc())
        )).scalars().all()
    )
    return [_agent_run_dict(r) for r in rows]


@router.get("/agent/runs/{run_id}")
async def get_agent_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    """Get a single AI agent run (ownership enforced via its scan)."""
    run = await db.get(AiAgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Agent run not found")
    await _own_scan(db, run.scan_id, current_user.id)
    return _agent_run_dict(run)


class ApprovalBody(BaseModel):
    approval_id: str
    decision: str = Field(pattern="^(allow|deny)$")


@router.post("/agent/runs/{run_id}/approval")
async def decide_agent_approval(
    run_id: str,
    body: ApprovalBody,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    """Operator allow/deny for an intrusive action a guided run is paused on.

    Signals the waiting agent (running in the worker) via Redis. The agent
    clears pending_approval itself once it reads the decision.
    """
    run = await db.get(AiAgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Agent run not found")
    await _own_scan(db, run.scan_id, current_user.id)

    import json as _json
    pending = _json.loads(run.pending_approval) if run.pending_approval else None
    if not pending or pending.get("approval_id") != body.approval_id:
        raise HTTPException(status_code=409, detail="No matching pending approval for this run")

    try:
        from scanr.db.redis import get_redis
        r = get_redis()
        await r.setex(f"scanr:ai:approval:{body.approval_id}", 600, body.decision)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not signal decision: {exc}")
    logger.info("agent approval %s for run %s by %s", body.decision, run_id, current_user.email)
    return {"ok": True, "decision": body.decision}
