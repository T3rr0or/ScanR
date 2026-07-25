"""Celery task: re-run one finding's plugin against its original target."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from .celery_app import celery_app
from .scan_tasks import _make_engine_and_session

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="scanr.retest_finding")
def retest_finding_task(self, retest_id: str) -> dict:
    return asyncio.run(_run_retest(retest_id))


async def _run_retest(retest_id: str) -> dict:
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from scanr.core import plugin_manager
    from scanr.core.context import ScanContext
    from scanr.core.retest import decide_verdict
    from scanr.core.scan_logger import ScanLogger
    from scanr.models import Finding, FindingRetest, Host, Port, Scan

    engine, session_maker = _make_engine_and_session()
    try:
        async with session_maker() as db:
            retest = await db.get(FindingRetest, retest_id)
            if retest is None:
                logger.warning("Retest %s vanished before it ran", retest_id)
                return {"status": "missing"}

            finding = await db.get(Finding, retest.finding_id)
            if finding is None:
                return await _fail(db, retest, "The finding no longer exists.")

            retest.status = "running"
            retest.started_at = datetime.now(timezone.utc)
            await db.commit()

            plugin_cls = plugin_manager.get_all_plugin_classes().get(finding.plugin_id)
            if plugin_cls is None:
                return await _fail(
                    db, retest,
                    f"Plugin {finding.plugin_id!r} is no longer available, so this "
                    f"finding cannot be re-verified automatically.",
                )

            if finding.host_id is None:
                return await _fail(
                    db, retest,
                    "This finding is not attached to a host, so there is nothing to re-check.",
                )

            host = (
                await db.execute(
                    select(Host)
                    .where(Host.id == finding.host_id)
                    .options(selectinload(Host.ports).selectinload(Port.service))
                )
            ).scalar_one_or_none()
            if host is None:
                return await _fail(db, retest, "The host record for this finding no longer exists.")

            scan = await db.get(Scan, finding.scan_id)
            if scan is None:
                return await _fail(db, retest, "The originating scan no longer exists.")

            scan_log = ScanLogger(scan.id)
            ctx = ScanContext(
                scan_id=scan.id, scan=scan, db=db, profile=scan.profile, log=scan_log
            )

            try:
                observed = await plugin_cls().check(ctx, host)
            except Exception as exc:  # noqa: BLE001 - a plugin crash is a failed retest, not a lost task
                logger.exception("Retest %s: plugin %s raised", retest_id, finding.plugin_id)
                return await _fail(db, retest, f"The check errored: {exc}")
            finally:
                await scan_log.close()

            observations = [
                {
                    "severity": getattr(o.severity, "value", str(o.severity)),
                    "title": o.title,
                    "evidence": getattr(o, "evidence", None),
                    "port_number": getattr(o, "port_number", None),
                }
                for o in (observed or [])
            ]

            outcome = decide_verdict(
                original_title=finding.title,
                original_port=finding.port_number,
                observations=observations,
                # A plugin that returns nothing for an unreachable host is
                # indistinguishable from one that returns nothing because the
                # issue is fixed, so use the host's recorded state as the guard.
                host_reachable=(host.status == "up"),
            )

            now = datetime.now(timezone.utc)
            retest.status = "completed"
            retest.verdict = outcome.verdict
            retest.evidence = outcome.evidence
            retest.finished_at = now

            finding.last_retest_at = now
            finding.last_retest_verdict = outcome.verdict
            await db.commit()

            logger.info(
                "Retest %s for finding %s: %s", retest_id, finding.id, outcome.verdict
            )
            return {"status": "completed", "verdict": outcome.verdict}
    finally:
        await engine.dispose()


async def _fail(db, retest, message: str) -> dict:
    retest.status = "failed"
    retest.error = message
    retest.finished_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "failed", "error": message}
