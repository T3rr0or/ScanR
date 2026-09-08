"""Assurance reporting — the checks that passed, not just the ones that failed.

The engine has always written one plugin_runs row per plugin per host; no report
surfaced it, so a clean scan produced a report indistinguishable from a shallow
one. These tests pin the aggregation a report reads.
"""
from types import SimpleNamespace

from scanr.reporting.coverage import Coverage, build_coverage


def _run(plugin_id, status="success", findings=0, host="h1"):
    return SimpleNamespace(
        plugin_id=plugin_id, status=status, findings_count=findings,
        host_id=host, host_ip="192.0.2.1", duration_ms=10, error=None,
    )


# ── aggregation ──────────────────────────────────────────────────────────────

def test_a_clean_run_counts_as_a_pass():
    c = build_coverage([_run("web.http_headers")])
    assert c.checks_run == 1
    assert c.checks_clean == 1
    assert c.checks_with_findings == 0
    assert c.clean_pct == 100.0


def test_a_run_with_findings_is_not_counted_as_a_pass():
    c = build_coverage([_run("web.http_headers", findings=3)])
    assert c.checks_clean == 0
    assert c.checks_with_findings == 1
    assert c.per_plugin[0].findings_total == 3


def test_distinct_plugins_and_hosts_are_counted():
    c = build_coverage([
        _run("a", host="h1"), _run("b", host="h1"),
        _run("a", host="h2"), _run("b", host="h2"),
    ])
    assert c.plugins_used == 2
    assert c.hosts_checked == 2
    assert c.checks_run == 4


def test_timeouts_and_failures_are_separated():
    c = build_coverage([
        _run("a", status="timeout"),
        _run("b", status="failed"),
        _run("c"),
    ])
    assert c.checks_timed_out == 1
    assert c.checks_failed == 1
    assert c.checks_incomplete == 2
    assert c.checks_completed == 1


def test_an_unknown_status_is_treated_as_a_failure_not_a_pass():
    """Fail safe: never let an unrecognised status inflate the pass count."""
    c = build_coverage([_run("a", status="something-new")])
    assert c.checks_clean == 0
    assert c.checks_failed == 1


# ── the percentages a reader will quote ──────────────────────────────────────

def test_clean_pct_is_measured_against_completed_not_attempted():
    """An incomplete check is not a pass; counting it would overstate assurance."""
    c = build_coverage([
        _run("a"), _run("b"),                  # 2 clean
        _run("c", status="timeout"),           # 1 never finished
    ])
    assert c.checks_completed == 2
    assert c.clean_pct == 100.0                # 2 of 2 completed
    assert c.completion_pct == 66.7            # 2 of 3 attempted


def test_percentages_are_zero_rather_than_dividing_by_zero():
    c = Coverage()
    assert c.clean_pct == 0.0
    assert c.completion_pct == 0.0


def test_empty_scan_produces_an_empty_summary():
    c = build_coverage([])
    assert c.checks_run == 0
    assert c.per_plugin == []


# ── surfacing the caveat ─────────────────────────────────────────────────────

def test_incomplete_plugins_are_listed_for_the_caveat():
    """A reader must know which checks cannot support 'no finding' claims."""
    c = build_coverage([
        _run("solid"), _run("solid", host="h2"),
        _run("flaky", status="timeout"), _run("flaky", host="h2"),
    ])
    names = [p.plugin_id for p in c.incomplete_plugins]
    assert names == ["flaky"]
    flaky = c.incomplete_plugins[0]
    assert flaky.incomplete == 1 and flaky.hosts_checked == 2


def test_per_plugin_is_ordered_by_findings_then_name():
    c = build_coverage([
        _run("quiet"), _run("loud", findings=9), _run("medium", findings=2),
    ])
    assert [p.plugin_id for p in c.per_plugin] == ["loud", "medium", "quiet"]


def test_missing_findings_count_is_treated_as_zero():
    run = _run("a")
    run.findings_count = None
    c = build_coverage([run])
    assert c.checks_clean == 1
    assert c.per_plugin[0].findings_total == 0
