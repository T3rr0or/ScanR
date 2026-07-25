"""`scanr ci` — the pipeline entry point.

The exit code *is* the product here, so these pin it. In particular they pin the
distinction CI depends on: 1 means "the scan ran and found things", 2 means "the
scan did not produce a verdict". Collapsing those makes a broken scanner
indistinguishable from a clean report.
"""
import json

import httpx
import pytest
from click.testing import CliRunner

from scanr.cli.main import _counts_at_or_above, cli

BASE = "http://scanr.test"


def counts(critical=0, high=0, medium=0, low=0, info=0):
    return {
        "findings_critical": critical, "findings_high": high,
        "findings_medium": medium, "findings_low": low, "findings_info": info,
    }


def api(monkeypatch, *, scan_status="completed", scan=None, on_request=None):
    """Route the CLI's httpx calls at an in-memory API."""
    scan_body = {"id": "scan-1", "status": scan_status, "hosts_up": 2, "hosts_total": 2,
                 **counts(), **(scan or {})}
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if on_request:
            override = on_request(request)
            if override is not None:
                return override
        path = request.url.path
        if path == "/api/v1/scans" and request.method == "POST":
            return httpx.Response(201, json={"id": "scan-1"})
        if path == "/api/v1/scans/scan-1/launch":
            return httpx.Response(200, json={"status": "queued"})
        if path == "/api/v1/scans/scan-1":
            return httpx.Response(200, json=scan_body)
        if path == "/api/v1/reports" and request.method == "POST":
            return httpx.Response(201, json={"id": "rep-1", "status": "pending"})
        if path == "/api/v1/reports/rep-1":
            return httpx.Response(200, json={"id": "rep-1", "status": "completed"})
        if path == "/api/v1/reports/rep-1/download":
            return httpx.Response(200, content=b'{"version":"2.1.0","runs":[]}')
        return httpx.Response(404, json={"detail": "not found"})

    transport = httpx.MockTransport(handler)
    real_request = httpx.request

    def patched(method, url, **kw):
        kw.pop("verify", None)
        with httpx.Client(transport=transport) as c:
            return c.request(method, url, **kw)

    monkeypatch.setattr(httpx, "request", patched)
    return seen, real_request


def run(*args):
    return CliRunner().invoke(
        cli, ["--url", BASE, "--token", "sk_test", "ci", *args], catch_exceptions=False
    )


# ── threshold arithmetic ─────────────────────────────────────────────────────

def test_threshold_counts_at_and_above():
    c = {"critical": 1, "high": 2, "medium": 4, "low": 8, "info": 16}
    assert _counts_at_or_above(c, "critical") == 1
    assert _counts_at_or_above(c, "high") == 3
    assert _counts_at_or_above(c, "medium") == 7
    assert _counts_at_or_above(c, "info") == 31


def test_threshold_handles_missing_and_null_counts():
    assert _counts_at_or_above({}, "high") == 0
    assert _counts_at_or_above({"critical": None, "high": 2}, "high") == 2


# ── exit codes ───────────────────────────────────────────────────────────────

def test_clean_scan_exits_zero(monkeypatch):
    api(monkeypatch)
    result = run("-t", "192.0.2.0/24", "--poll-interval", "0")
    assert result.exit_code == 0, result.output
    assert "No findings at or above" in result.output


def test_findings_at_threshold_exit_one(monkeypatch):
    api(monkeypatch, scan=counts(high=3))
    result = run("-t", "192.0.2.0/24", "--fail-on", "high", "--poll-interval", "0")
    assert result.exit_code == 1, result.output
    assert "3 finding(s) at or above 'high'" in result.output


def test_findings_below_threshold_exit_zero(monkeypatch):
    """A medium must not fail a build configured to break on high."""
    api(monkeypatch, scan=counts(medium=9, low=20))
    result = run("-t", "192.0.2.0/24", "--fail-on", "high", "--poll-interval", "0")
    assert result.exit_code == 0, result.output


def test_fail_on_never_always_exits_zero(monkeypatch):
    """Report-only mode, for teams adopting the scanner before enforcing it."""
    api(monkeypatch, scan=counts(critical=5))
    result = run("-t", "192.0.2.0/24", "--fail-on", "never", "--poll-interval", "0")
    assert result.exit_code == 0, result.output


def test_failed_scan_exits_two_not_one(monkeypatch):
    """A scan that errored produced no verdict — reporting it as 'clean' would
    hide a broken pipeline, and as 'findings' would be a lie."""
    api(monkeypatch, scan_status="failed",
        scan={"error_message": "Forbidden target resolved: 127.0.0.1"})
    result = run("-t", "192.0.2.0/24", "--poll-interval", "0")
    assert result.exit_code == 2, result.output
    assert "Forbidden target" in result.output


def test_cancelled_scan_exits_two(monkeypatch):
    api(monkeypatch, scan_status="cancelled")
    result = run("-t", "192.0.2.0/24", "--poll-interval", "0")
    assert result.exit_code == 2


def test_api_error_exits_two(monkeypatch):
    api(monkeypatch, on_request=lambda r: httpx.Response(500, json={"detail": "boom"})
        if r.url.path == "/api/v1/scans" else None)
    result = run("-t", "192.0.2.0/24", "--poll-interval", "0")
    assert result.exit_code == 2, result.output


def test_timeout_exits_two(monkeypatch):
    api(monkeypatch, scan_status="running")
    result = run("-t", "192.0.2.0/24", "--timeout", "0", "--poll-interval", "0")
    assert result.exit_code == 2, result.output
    assert "Timed out" in result.output


def test_missing_token_exits_two_before_calling_anything(monkeypatch):
    seen, _ = api(monkeypatch)
    result = CliRunner().invoke(cli, ["--url", BASE, "ci", "-t", "192.0.2.0/24"],
                                catch_exceptions=False)
    assert result.exit_code == 2
    assert "No token" in result.output
    assert seen == [], "must not hit the API without credentials"


# ── SARIF ────────────────────────────────────────────────────────────────────

def test_sarif_is_written_when_requested(monkeypatch, tmp_path):
    api(monkeypatch)
    out = tmp_path / "results.sarif"
    result = run("-t", "192.0.2.0/24", "--sarif", str(out), "--poll-interval", "0")
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_sarif_failure_does_not_change_the_verdict(monkeypatch, tmp_path):
    """The scan already ran; a reporting hiccup must not turn a pass into a fail
    or vice versa."""
    api(monkeypatch, scan=counts(critical=1),
        on_request=lambda r: httpx.Response(500, json={"detail": "no"})
        if r.url.path == "/api/v1/reports" and r.method == "POST" else None)
    out = tmp_path / "results.sarif"
    result = run("-t", "192.0.2.0/24", "--sarif", str(out),
                 "--fail-on", "critical", "--poll-interval", "0")
    assert result.exit_code == 1, "the finding still decides the build"
    assert not out.exists()


def test_no_sarif_requested_means_no_report_call(monkeypatch):
    seen, _ = api(monkeypatch)
    run("-t", "192.0.2.0/24", "--poll-interval", "0")
    assert not any(path.startswith("/api/v1/reports") for _m, path in seen)


# ── request shape ────────────────────────────────────────────────────────────

def test_multiple_targets_are_sent_together(monkeypatch):
    captured = {}

    def spy(request):
        if request.url.path == "/api/v1/scans" and request.method == "POST":
            captured.update(json.loads(request.content))
        return None

    api(monkeypatch, on_request=spy)
    run("-t", "192.0.2.10", "-t", "192.0.2.11", "--poll-interval", "0")
    assert captured["targets"] == ["192.0.2.10", "192.0.2.11"]


def test_profile_json_is_passed_through(monkeypatch):
    captured = {}

    def spy(request):
        if request.url.path == "/api/v1/scans" and request.method == "POST":
            captured.update(json.loads(request.content))
        return None

    api(monkeypatch, on_request=spy)
    run("-t", "192.0.2.10", "--profile", "custom",
        "--profile-json", '{"port_range":"top-1000"}', "--poll-interval", "0")
    assert captured["profile"] == "custom"
    assert captured["profile_json"] == '{"port_range":"top-1000"}'


def test_scan_is_launched_not_just_created(monkeypatch):
    seen, _ = api(monkeypatch)
    run("-t", "192.0.2.10", "--poll-interval", "0")
    assert ("POST", "/api/v1/scans/scan-1/launch") in seen


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_every_threshold_is_accepted(monkeypatch, severity):
    api(monkeypatch)
    assert run("-t", "192.0.2.10", "--fail-on", severity,
               "--poll-interval", "0").exit_code == 0
