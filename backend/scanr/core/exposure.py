"""Exposure over time: how many issues were open each week, and how fast they close.

ScanR stores one finding row per scan, so the same problem found by four weekly
scans is four rows. Trends are computed over *issues* instead: findings with the
same owner, host IP, plugin, port and title (the same identity triage
carry-forward and SARIF use). An issue is

* opened when it is first seen;
* fixed when a later scan successfully ran the same plugin on the same host
  and did not report it again (the plugin_runs table proves the check ran,
  so a narrower scan that skipped the check never counts as a fix);
* resolved / accepted when its latest row says so (closed at triage time);
* ignored entirely when its latest row is marked false positive.

An issue that comes back after a fix is treated as open since it was first
seen; gaps are not modelled.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.models import Finding, Host, PluginRun, Scan

SEVERITIES = ("critical", "high", "medium", "low")


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


@dataclass
class Issue:
    title: str
    ip: str | None
    port: int | None
    severity: str
    first_seen: datetime
    last_seen: datetime
    priority: float | None
    kev: bool
    closed_at: datetime | None = None
    closed_how: str | None = None  # fixed | resolved | accepted

    def open_at(self, when: datetime) -> bool:
        return self.first_seen <= when and (self.closed_at is None or self.closed_at > when)

    @property
    def remediated(self) -> bool:
        return self.closed_how in ("fixed", "resolved")


async def load_issues(db: AsyncSession, user_id: str) -> list[Issue]:
    rows = (await db.execute(
        select(
            Finding.scan_id, Finding.plugin_id, Finding.port_number, Finding.title, Finding.severity,
            Finding.created_at, Finding.remediation_status, Finding.false_positive, Finding.triaged_at,
            Finding.priority_score, Finding.is_kev, Host.ip,
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .outerjoin(Host, Finding.host_id == Host.id)
        .where(Scan.user_id == user_id, Finding.severity.in_(SEVERITIES))
        .order_by(Finding.created_at)
    )).all()

    observations: dict[tuple, list] = defaultdict(list)
    for row in rows:
        observations[(row.ip, row.plugin_id, row.port_number, row.title)].append(row)

    runs: dict[tuple[str | None, str], list[tuple[datetime, str]]] = defaultdict(list)
    for run in (await db.execute(
        select(PluginRun.host_ip, PluginRun.plugin_id, PluginRun.created_at, PluginRun.scan_id)
        .join(Scan, PluginRun.scan_id == Scan.id)
        .where(Scan.user_id == user_id, PluginRun.status == "success")
        .order_by(PluginRun.created_at)
    )).all():
        runs[(run.host_ip, run.plugin_id)].append((_utc(run.created_at), run.scan_id))

    issues: list[Issue] = []
    for (ip, plugin_id, port, title), seen in observations.items():
        latest = seen[-1]
        if latest.false_positive:
            continue
        issue = Issue(
            title=title, ip=ip, port=port, severity=latest.severity,
            first_seen=_utc(seen[0].created_at), last_seen=_utc(latest.created_at),
            priority=latest.priority_score, kev=bool(latest.is_kev),
        )
        if latest.remediation_status in ("resolved", "accepted_risk"):
            issue.closed_at = _utc(latest.triaged_at or latest.created_at)
            issue.closed_how = "resolved" if latest.remediation_status == "resolved" else "accepted"
        else:
            scans_seen = {r.scan_id for r in seen}
            for ran_at, scan_id in runs.get((ip, plugin_id), []):
                # The run row is written after the plugin's findings, so a run in
                # a scan that did report the issue is not evidence of a fix.
                if ran_at > issue.last_seen and scan_id not in scans_seen:
                    issue.closed_at, issue.closed_how = ran_at, "fixed"
                    break
        issues.append(issue)
    return issues


def _days(delta: timedelta) -> float:
    return delta.total_seconds() / 86400


def summarize(issues: list[Issue], weeks: int, sla_days: dict[str, int], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    points = []
    for i in range(weeks, -1, -1):
        at = now - timedelta(weeks=i)
        start = at - timedelta(weeks=1)
        open_ = [x for x in issues if x.open_at(at)]
        points.append({
            "date": at.date().isoformat(),
            **{sev: sum(1 for x in open_ if x.severity == sev) for sev in SEVERITIES},
            "fix_now": sum(1 for x in open_ if (x.priority or 0) >= 80),
            "kev": sum(1 for x in open_ if x.kev),
            "new": sum(1 for x in issues if start < x.first_seen <= at),
            "fixed": sum(1 for x in issues if x.remediated and x.closed_at and start < x.closed_at <= at),
        })

    window_start = now - timedelta(weeks=weeks)
    closed_in_window = [x for x in issues if x.remediated and x.closed_at and x.closed_at > window_start]
    open_now = [x for x in issues if x.open_at(now)]
    by_severity = {}
    for sev in SEVERITIES:
        target = sla_days[sev]
        durations = [_days(x.closed_at - x.first_seen) for x in closed_in_window if x.severity == sev and x.closed_at]
        open_sev = [x for x in open_now if x.severity == sev]
        by_severity[sev] = {
            "sla_days": target,
            "open": len(open_sev),
            "overdue": sum(1 for x in open_sev if _days(now - x.first_seen) > target),
            "fixed": len(durations),
            "mean_days_to_fix": round(statistics.fmean(durations), 1) if durations else None,
            "median_days_to_fix": round(statistics.median(durations), 1) if durations else None,
            "fixed_within_sla": round(sum(1 for d in durations if d <= target) / len(durations), 3) if durations else None,
        }

    overdue = sorted(
        (x for x in open_now if _days(now - x.first_seen) > sla_days[x.severity]),
        key=lambda x: (-(x.priority or 0), x.first_seen),
    )[:10]
    return {
        "generated_at": now.isoformat(),
        "weeks": weeks,
        "points": points,
        "by_severity": by_severity,
        "overdue": [
            {
                "title": x.title,
                "location": f"{x.ip or '-'}{f':{x.port}' if x.port else ''}",
                "severity": x.severity,
                "priority": x.priority,
                "kev": x.kev,
                "age_days": round(_days(now - x.first_seen), 1),
                "sla_days": sla_days[x.severity],
            }
            for x in overdue
        ],
    }
