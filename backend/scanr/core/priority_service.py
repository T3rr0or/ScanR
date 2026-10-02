"""Apply scanr.core.priority to stored findings."""
from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import ColumnElement

from scanr.core import priority
from scanr.models import Finding, Host, Scan

logger = logging.getLogger(__name__)

_BATCH = 500


def _cve_list(finding: Finding) -> list[str]:
    if not finding.cve_ids:
        return []
    try:
        value = json.loads(finding.cve_ids)
    except ValueError:
        return []
    return [str(c) for c in value] if isinstance(value, list) else []


async def _threat_data(cves: list[str]) -> tuple[dict[str, tuple[float, float]], frozenset[str]]:
    from scanr.plugins.cve import epss
    from scanr.plugins.cve.kev_cache import aget_kev_cve_ids

    try:
        kev = await aget_kev_cve_ids()
    except Exception:
        kev = frozenset()
    scores = await asyncio.to_thread(epss.lookup, cves) if cves else {}
    return scores, kev


async def _host_tags(db: AsyncSession, pairs: set[tuple[str, str]]) -> dict[tuple[str, str], set[str]]:
    from scanr.api.v1.host_tags import HostTag

    tags: dict[tuple[str, str], set[str]] = defaultdict(set)
    if not pairs:
        return tags
    users = {u for u, _ in pairs}
    ips = {ip for _, ip in pairs}
    rows = await db.execute(
        select(HostTag.user_id, HostTag.ip, HostTag.tag).where(HostTag.user_id.in_(users), HostTag.ip.in_(ips))
    )
    for user_id, ip, tag in rows.all():
        tags[(user_id, ip)].add(tag)
    return tags


def _apply(finding: Finding, result: priority.Priority) -> None:
    finding.priority_score = result.score
    finding.priority_reasons = json.dumps(result.reasons)
    finding.epss_score = result.epss_score
    finding.epss_percentile = result.epss_percentile
    finding.is_kev = result.is_kev


async def score_rows(db: AsyncSession, rows: list[tuple[Finding, str | None, str]]) -> None:
    """Score (finding, host_ip, user_id) rows in place. The caller commits."""
    cves = sorted({c for f, _, _ in rows for c in _cve_list(f)})
    scores, kev = await _threat_data(cves)
    tags = await _host_tags(db, {(user_id, ip) for _, ip, user_id in rows if ip})
    for finding, ip, user_id in rows:
        _apply(finding, priority.compute(
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            cve_ids=_cve_list(finding),
            epss=scores,
            kev=kev,
            validated=finding.validated,
            host_ip=ip,
            host_tags=tags.get((user_id, ip), set()) if ip else set(),
        ))


async def rescore(db: AsyncSession, *conditions: ColumnElement[bool]) -> int:
    """Re-score every finding matching ``conditions``, committing per batch."""
    total = 0
    last_id = ""
    while True:
        q = (
            select(Finding, Host.ip, Scan.user_id)
            .outerjoin(Host, Finding.host_id == Host.id)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Finding.id > last_id, *conditions)
            .order_by(Finding.id)
            .limit(_BATCH)
        )
        rows = [(f, ip, user_id) for f, ip, user_id in (await db.execute(q)).all()]
        if not rows:
            return total
        await score_rows(db, rows)
        await db.commit()
        total += len(rows)
        last_id = rows[-1][0].id


async def rescore_host(db: AsyncSession, user_id: str, ip: str) -> int:
    """After a host's tags change: re-score that user's findings on that IP."""
    host_ids = select(Host.id).join(Scan, Host.scan_id == Scan.id).where(Scan.user_id == user_id, Host.ip == ip)
    return await rescore(db, Finding.host_id.in_(host_ids))
