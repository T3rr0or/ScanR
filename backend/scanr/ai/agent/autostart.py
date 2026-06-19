"""Auto-launch an AI agent run for a scan that opted in at creation time.

When a scan is created with ``ai_agent.enabled``, the worker calls
:func:`launch_scan_agent` as the scan starts so the agent investigates
concurrently while the scan runs (rather than requiring a manual click after).
Failures here never break the scan — the agent is best-effort.
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Objective used when the user didn't supply one. It tells the agent the scan is
# live so it keeps investigating as new hosts/findings appear, instead of
# concluding early on a still-sparse result set.
_DEFAULT_LIVE_OBJECTIVE = (
    "This scan is running right now and its hosts and findings will grow over "
    "time. Investigate continuously: re-check the scan's hosts and findings as "
    "they appear, corroborate the most serious and exploitable issues with the "
    "available tools, and build a prioritized assessment with concrete next "
    "steps. Do not stop just because results look sparse early — new data is "
    "still arriving."
)


async def build_scan_agent_run(db: AsyncSession, scan, *, objective: str | None = None):
    """Create and persist the AiAgentRun for a scan that opted into AI.

    Returns the committed run, or ``None`` if AI is disabled or not runnable
    (e.g. no API key configured). Does NOT start execution — callers decide
    whether to enqueue it (concurrent) or drive it inline (engine steering).
    """
    if not getattr(scan, "ai_agent_enabled", False):
        return None

    from scanr.ai import settings_store as store
    from scanr.models.ai_agent_run import AiAgentRun
    from scanr.models.base import new_uuid

    provider_name = scan.ai_agent_provider or await store.get_default_provider(db)
    if not await store.resolve_api_key(db, provider_name):
        logger.warning(
            "Scan %s requested AI but no API key is configured for provider %r; skipping",
            scan.id, provider_name,
        )
        return None

    run = AiAgentRun(
        id=new_uuid(),
        scan_id=scan.id,
        status="queued",
        mode=scan.ai_agent_mode or "guided",
        objective=(objective or scan.ai_agent_objective or "").strip() or _DEFAULT_LIVE_OBJECTIVE,
        provider=provider_name,
        model=scan.ai_agent_model,
        capabilities=scan.ai_agent_capabilities,  # already a JSON string (or None)
    )
    db.add(run)
    await db.commit()
    return run


async def launch_scan_agent(db: AsyncSession, scan) -> str | None:
    """Create and enqueue a concurrent AI agent run for ``scan`` if it opted in."""
    run = await build_scan_agent_run(db, scan)
    if run is None:
        return None

    from scanr.tasks.agent_tasks import run_ai_agent_task

    run_ai_agent_task.delay(run.id)
    logger.info("Launched concurrent AI agent run %s for scan %s (%s)", run.id, scan.id, run.mode)
    return run.id
