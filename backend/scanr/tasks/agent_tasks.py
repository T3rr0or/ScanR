"""Celery task: run a guided/autonomous AI agent against a scan."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from scanr.ai.llm.base import Msg, Usage

from .celery_app import celery_app
from .scan_tasks import _make_engine_and_session

logger = logging.getLogger(__name__)


@celery_app.task(name="scanr.run_ai_agent")
def run_ai_agent_task(run_id: str, resume: bool = False) -> dict:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run_agent_async(run_id, resume=resume))
    finally:
        loop.close()


@celery_app.task(name="scanr.reap_stale_agent_runs")
def reap_stale_agent_runs() -> dict:
    """Watchdog: fail agent runs whose worker died mid-run.

    Without this, a run whose worker was OOM/SIGKILLed stays "running" forever —
    the chat endpoint then rejects every follow-up with 409 and the UI spins
    indefinitely. Runs whose heartbeat (or, for queued rows that never started,
    creation time) is older than ``ai_agent_heartbeat_timeout`` are marked failed.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_reap_stale_agent_runs_async())
    finally:
        loop.close()


async def _reap_stale_agent_runs_async() -> dict:
    from datetime import timedelta

    from sqlalchemy import or_, select, update

    from scanr.config import get_settings
    from scanr.models import AiAgentRun

    settings = get_settings()
    now = datetime.now(tz=timezone.utc)
    cutoff = now - timedelta(seconds=settings.ai_agent_heartbeat_timeout)

    engine, SessionLocal = _make_engine_and_session()
    try:
        async with SessionLocal() as db:
            result = await db.execute(
                select(AiAgentRun.id).where(
                    AiAgentRun.status.in_(("running", "queued")),
                    or_(
                        AiAgentRun.last_heartbeat < cutoff,
                        (AiAgentRun.last_heartbeat.is_(None)) & (AiAgentRun.created_at < cutoff),
                    ),
                )
            )
            stale_ids = [row[0] for row in result.all()]
            if stale_ids:
                await db.execute(
                    update(AiAgentRun)
                    .where(AiAgentRun.id.in_(stale_ids), AiAgentRun.status.in_(("running", "queued")))
                    .values(
                        status="failed",
                        error="Agent run timed out — the worker went unresponsive (stale heartbeat).",
                        pending_approval=None,
                    )
                )
                await db.commit()
                logger.warning("reaped %d stale agent run(s): %s", len(stale_ids), stale_ids)
            return {"reaped": len(stale_ids)}
    finally:
        await engine.dispose()


async def _run_agent_async(run_id: str, resume: bool = False) -> dict:
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
            run.last_heartbeat = datetime.now(tz=timezone.utc)
            await db.commit()

            # Drop any stale cancel flag from a prior run so a fresh/resumed run
            # isn't stopped on its first iteration. Stop sets this flag.
            # NOTE: get_redis()'s pool only exists in the API process lifespan —
            # in this Celery worker it always raises RuntimeError. Open a throwaway
            # client instead (same pattern as the post-run cleanup below).
            try:
                import redis.asyncio as aioredis

                r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
                await r.delete(f"scanr:ai:cancel:{run_id}")
                await r.aclose()
            except Exception:  # noqa: BLE001 - best-effort
                pass

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
                    allow_command_exec=bool(caps.get("allow_command_exec")),
                )
                # None = engine default; 0 = unlimited (operator stops manually).
                # Per-minute input token cap: None on the run falls back to the
                # global setting, 0 explicitly disables the cap for this run.
                rpm_cap = (
                    run.rate_limit_tokens_per_min
                    if run.rate_limit_tokens_per_min is not None
                    else max(settings.ai_rate_limit_tokens_per_min, 0)
                )
                budget = Budget(
                    max_tokens=(
                        run.max_tokens
                        if run.max_tokens is not None
                        else max(settings.ai_max_tokens * 20, 100_000)
                    ),
                    max_iterations=(
                        run.max_iterations if run.max_iterations is not None else Budget.max_iterations
                    ),
                    max_input_tokens_per_minute=rpm_cap,
                )
                ctx = DbAgentContext(
                    scan_id=run.scan_id,
                    db=db,
                    policy=policy,
                    budget=budget,
                    denylist=settings.scan_denylist,
                    logger=slog,
                    run_id=run.id,
                )
                await slog.info(
                    f"AI agent {'resumed' if resume else 'started'} ({run.mode}, {provider.name}/{provider.model})",
                    phase="ai_agent",
                )

                # Persist the transcript live so the UI shows progress mid-run,
                # not only at the end.
                acc: list[dict] = []

                async def _on_action(a):
                    acc.append({"tool": a.tool, "arguments": a.arguments, "result": a.result[:4000]})
                    run.actions = json.dumps(acc)
                    run.last_heartbeat = datetime.now(tz=timezone.utc)
                    await db.commit()

                async def _on_step(msgs):
                    # Stream the conversation to the DB after each turn so the
                    # chat UI updates live, not only when the run finishes.
                    run.conversation = json.dumps(_serialize_conversation(msgs))
                    run.last_heartbeat = datetime.now(tz=timezone.utc)
                    await db.commit()

                # On resume, load conversation + previous usage to continue from
                # where the user left off.
                all_messages: list = []
                prev_usage = Usage()
                prev_iterations = 0
                if resume:
                    raw_conv = json.loads(run.conversation) if run.conversation else []
                    all_messages = _deserialize_conversation(raw_conv)
                    if run.token_usage:
                        tu = json.loads(run.token_usage)
                        prev_usage = Usage(
                            input_tokens=tu.get("input_tokens", 0),
                            output_tokens=tu.get("output_tokens", 0),
                            cached_input_tokens=tu.get("cached_input_tokens", 0),
                        )
                    prev_actions = json.loads(run.actions) if run.actions else []
                    prev_iterations = len(prev_actions)
                    acc = list(prev_actions)

                result, all_messages = await run_agent(
                    provider,
                    ctx,
                    default_registry(policy),
                    objective=run.objective,
                    scan_summary=_scan_summary(scan),
                    on_action=_on_action,
                    on_step=_on_step,
                    messages=all_messages if all_messages else None,
                    usage=prev_usage,
                    iterations=prev_iterations,
                )

                # Serialize the full conversation so future resumes see all history.
                run.conversation = json.dumps(_serialize_conversation(all_messages))

                # A user Stop ends the run normally (stop_reason='stopped') so it
                # stays resumable — the reason is carried by stop_reason, not status.
                run.status = "completed"
                run.provider = provider.name
                run.model = provider.model
                run.stop_reason = result.stop_reason
                run.final_text = result.final_text
                run.actions = json.dumps(
                    [{"tool": a.tool, "arguments": a.arguments, "result": a.result[:4000]} for a in result.actions]
                )
                run.token_usage = json.dumps(
                    {
                        "input_tokens": result.usage.input_tokens,
                        "output_tokens": result.usage.output_tokens,
                        "cached_input_tokens": result.usage.cached_input_tokens,
                    }
                )
                # Human-readable reason for the live scan console.
                _reason = {
                    "end": "completed its assessment",
                    "max_iterations": f"reached the step limit ({budget.max_iterations} steps)",
                    "budget": f"reached the token safety limit (~{budget.max_tokens // 1000}k tokens)",
                    "stopped": "was stopped by the operator",
                }.get(result.stop_reason, result.stop_reason)
                await slog.info(
                    f"AI agent {_reason} after {len(result.actions)} step(s).",
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
                # Screenshot the pages the agent fetched into the Screenshots tab.
                try:
                    await ctx.flush_web_screenshots()
                except Exception:  # noqa: BLE001 - best-effort (incl. early-failure NameError)
                    pass
                # Clear any stop flag so a later resume doesn't stop immediately.
                try:
                    import redis.asyncio as aioredis

                    r = aioredis.from_url(settings.redis_url, decode_responses=True)
                    await r.delete(f"scanr:ai:cancel:{run.id}")
                    await r.aclose()
                except Exception:  # noqa: BLE001 - best-effort
                    pass
                # Tear down the agent's persistent sandbox session (if any).
                try:
                    from scanr.sandbox.client import SandboxClient

                    sbx = SandboxClient.from_settings()
                    if sbx is not None:
                        await sbx.close(run_id=run.id)
                except Exception:  # noqa: BLE001 - teardown is best-effort
                    pass
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


def _serialize_conversation(messages: list[Msg]) -> list[dict]:
    """Serialize Msg list to JSON-compatible dicts for DB storage."""
    out: list[dict] = []
    for m in messages:
        d: dict = {"role": m.role, "content": m.content}
        if m.tool_calls:
            d["tool_calls"] = [{"id": tc.id, "name": tc.name, "arguments": tc.arguments} for tc in m.tool_calls]
        if m.tool_call_id:
            d["tool_call_id"] = m.tool_call_id
        if m.name:
            d["name"] = m.name
        out.append(d)
    return out


def _deserialize_conversation(raw: list[dict]) -> list[Msg]:
    """Deserialize conversation dicts back to Msg objects."""
    from scanr.ai.llm.base import ToolCall

    out: list[Msg] = []
    for d in raw:
        tcs = []
        for tc in d.get("tool_calls") or []:
            tcs.append(ToolCall(id=tc["id"], name=tc["name"], arguments=tc["arguments"]))
        out.append(
            Msg(
                role=d["role"],
                content=d.get("content", ""),
                tool_calls=tcs,
                tool_call_id=d.get("tool_call_id"),
                name=d.get("name"),
            )
        )
    return out
