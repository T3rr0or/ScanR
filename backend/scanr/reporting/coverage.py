"""Assurance reporting: what was checked, not just what was wrong.

A report that lists only findings cannot distinguish "we ran 114 checks against
this host and 110 of them passed" from "we barely scanned it". For a pentest
deliverable the negative evidence is most of the value — it is what lets a
reader trust a short findings list instead of suspecting a shallow scan.

The engine already records one `plugin_runs` row per plugin per host, with its
status, duration and finding count. Nothing surfaced it. This aggregates those
rows into the shape a report needs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Statuses the engine writes (see ScanEngine._record_plugin_run).
STATUS_SUCCESS = "success"
STATUS_TIMEOUT = "timeout"


@dataclass
class PluginCoverage:
    """How one plugin fared across every host it ran against."""
    plugin_id: str
    hosts_checked: int = 0
    clean: int = 0            # ran, found nothing — the assurance case
    with_findings: int = 0
    timed_out: int = 0
    failed: int = 0
    findings_total: int = 0

    @property
    def completed(self) -> int:
        return self.clean + self.with_findings

    @property
    def incomplete(self) -> int:
        """Runs that did not finish, so their host has no verdict from this check."""
        return self.timed_out + self.failed


@dataclass
class Coverage:
    """Scan-wide assurance summary."""
    checks_run: int = 0
    checks_clean: int = 0
    checks_with_findings: int = 0
    checks_timed_out: int = 0
    checks_failed: int = 0
    plugins_used: int = 0
    hosts_checked: int = 0
    per_plugin: list[PluginCoverage] = field(default_factory=list)

    @property
    def checks_completed(self) -> int:
        return self.checks_clean + self.checks_with_findings

    @property
    def checks_incomplete(self) -> int:
        return self.checks_timed_out + self.checks_failed

    @property
    def completion_pct(self) -> float:
        """Share of attempted checks that produced a verdict."""
        if not self.checks_run:
            return 0.0
        return round(100.0 * self.checks_completed / self.checks_run, 1)

    @property
    def clean_pct(self) -> float:
        """Share of *completed* checks that found nothing.

        Deliberately measured against completed rather than attempted runs: an
        incomplete check is not a pass, and counting it as one would overstate
        assurance.
        """
        if not self.checks_completed:
            return 0.0
        return round(100.0 * self.checks_clean / self.checks_completed, 1)

    @property
    def incomplete_plugins(self) -> list[PluginCoverage]:
        """Checks a reader should know did not finish everywhere."""
        return [p for p in self.per_plugin if p.incomplete]


def build_coverage(runs) -> Coverage:
    """Aggregate `plugin_runs` rows into a Coverage summary."""
    summary = Coverage()
    by_plugin: dict[str, PluginCoverage] = {}
    hosts: set[str] = set()

    for run in runs:
        summary.checks_run += 1
        if run.host_id:
            hosts.add(run.host_id)
        entry = by_plugin.setdefault(run.plugin_id, PluginCoverage(plugin_id=run.plugin_id))
        entry.hosts_checked += 1
        findings = run.findings_count or 0
        entry.findings_total += findings

        if run.status == STATUS_SUCCESS:
            if findings:
                entry.with_findings += 1
                summary.checks_with_findings += 1
            else:
                entry.clean += 1
                summary.checks_clean += 1
        elif run.status == STATUS_TIMEOUT:
            entry.timed_out += 1
            summary.checks_timed_out += 1
        else:
            entry.failed += 1
            summary.checks_failed += 1

    summary.plugins_used = len(by_plugin)
    summary.hosts_checked = len(hosts)
    # Noisiest first, then alphabetical, so a reader sees what mattered.
    summary.per_plugin = sorted(
        by_plugin.values(), key=lambda p: (-p.findings_total, p.plugin_id)
    )
    return summary
