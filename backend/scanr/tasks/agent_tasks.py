"""Celery task: run a guided/autonomous AI agent against a scan."""
from __future__ import annotations

import asyncio
import json
import logging

from .celery_app import celery_app
from .scan_tasks import _make_engine_and_session

logger = logging.getLogger(__name__)


@celery_app.task(name="scanr.run_ai_agent")
def run_ai_agent_task(run_id: str) -> dict:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run_agent_async(run_id))
    finally:
        loop.close()


async def _run_agent_async(run_id: str) -> dict:
    from scanr.ai import settings_store as store
    from scanr.ai.agent.db_context import DbAgentContext
    from scanr.ai.agent.loop import run_agent
    from scanr.ai.agent.policy import AgentPolicy, AutonomyMode, Budget
    from scanr.ai.agent.tools import default_registry
    from scanr.ai.llm.factory import AIProviderError, build_provider
    from scanr.config import get_settings
    from scanr.core.scan_logger import ScanLogger
    from scanr.models import AiAgentRun, Scan

    engine, SessionLocal = _make_engine_and_session()
    try:
        async with SessionLocal() as db:
            run = await db.get(AiAgentRun, run_id)
            if run is None:
                return {"error": "run not found"}
            run.status = "running"
            await db.commit()

            scan = await db.get(Scan, run.scan_id)
            slog = ScanLogger(run.scan_id)
            settings = get_settings()

            try:
                provider_name = run.provider or await store.get_default_provider(db)
                model = run.model or (await store.get_model(db, provider_name)) or None
                api_key = await store.resolve_api_key(db, provider_name)
                provider = build_provider(provider_name, model, api_key=api_key)

                caps = json.loads(run.capabilities) if run.capabilities else {}
                policy = AgentPolicy(
                    mode=AutonomyMode(run.mode),
                    aggressive=bool(caps.get("aggressive")),
                    allow_privilege_escalation=bool(caps.get("allow_privilege_escalation")),
                    allow_exploitation=bool(caps.get("allow_exploitation")),
                )
                budget = Budget(max_tokens=max(settings.ai_max_tokens * 20, 100_000))
                ctx = DbAgentContext(
                    scan_id=run.scan_id,
                    db=db,
                    policy=policy,
                    budget=budget,
                    denylist=settings.scan_denylist,
                    logger=slog,
                    run_id=run.id,
                )
                await slog.info(f"AI agent started ({run.mode}, {provider.name}/{provider.model})", phase="ai_agent")

                # Persist the transcript live so the UI shows progress mid-run,
                # not only at the end.
                acc: list[dict] = []

                async def _on_action(a):
                    acc.append({"tool": a.tool, "arguments": a.arguments, "result": a.result[:4000]})
                    run.actions = json.dumps(acc)
                    await db.commit()

                result = await run_agent(
                    provider,
                    ctx,
                    default_registry(),
                    objective=run.objective,
                    scan_summary=_scan_summary(scan),
                    on_action=_on_action,
                )

                run.status = "completed"
                run.provider = provider.name
                run.model = provider.model
                run.stop_reason = result.stop_reason
                run.final_text = result.final_text
                run.actions = json.dumps([
                    {"tool": a.tool, "arguments": a.arguments, "result": a.result[:4000]}
                    for a in result.actions
                ])
                run.token_usage = json.dumps({
                    "input_tokens": result.usage.input_tokens,
                    "output_tokens": result.usage.output_tokens,
                    "cached_input_tokens": result.usage.cached_input_tokens,
                })
                await slog.info(
                    f"AI agent finished ({result.stop_reason}); {len(result.actions)} action(s)",
                    phase="ai_agent",
                )
            except (AIProviderError, RuntimeError) as exc:
                run.status = "failed"
                run.error = str(exc)
                await slog.error(f"AI agent failed: {exc}", phase="ai_agent")
            except Exception as exc:  # noqa: BLE001
                logger.exception("AI agent run %s crashed", run_id)
                run.status = "failed"
                run.error = str(exc)
                await slog.error(f"AI agent error: {exc}", phase="ai_agent")
            finally:
                await db.commit()
                await slog.close()
            return {"run_id": run_id, "status": run.status}
    finally:
        await engine.dispose()


def _scan_summary(scan) -> str:
    if scan is None:
        return ""
    summary = (
        f"Scan '{scan.name}' — status {scan.status}; hosts up {scan.hosts_up}/{scan.hosts_total}; "
        f"findings: {scan.findings_critical} critical, {scan.findings_high} high, "
        f"{scan.findings_medium} medium, {scan.findings_low} low, {scan.findings_info} info."
    )
    if str(scan.status) == "running":
        summary += (
            " NOTE: this scan is STILL RUNNING — results are partial and more hosts/findings "
            "will appear. Prioritize guiding the live engagement; re-check the data as it grows."
        )
    return summary
