"""SARIF export, validated against the official 2.1.0 schema.

A SARIF file that does not validate is worse than no export: the failure surfaces
at upload time in GitHub code scanning or DefectDojo, with an error message about
someone else's schema, long after the scan. So the schema is vendored
(tests/fixtures/) and every shape the renderer can emit is checked against it
here — including the ones that only occur for a scan that never finished.
"""
import json
import types
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

from scanr.reporting.sarif_renderer import _fingerprint, render_sarif

_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "sarif-schema-2.1.0.json").read_text()
)


def finding(**kw):
    base = dict(
        plugin_id="services.ftp_anon", severity="high",
        title="Anonymous FTP login allowed",
        description="The FTP service permits anonymous login.",
        remediation="Disable anonymous FTP.", cve_ids=None, cvss_score=7.5,
        false_positive=False, remediation_status="open", analyst_notes=None,
        evidence="230 Login successful.", port_number=21, host_ip="192.0.2.10",
        validated=False, validation_method=None,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def scan(**kw):
    base = dict(
        id="scan-1", name="demo", status="completed", hosts_up=3,
        started_at=datetime.now(timezone.utc), finished_at=datetime.now(timezone.utc),
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


async def _render(tmp_path, findings, sc=None, name="r1") -> dict:
    from scanr.reporting import sarif_renderer

    sarif_renderer.settings.reports_dir = tmp_path
    out = await render_sarif({"scan": sc or scan(), "findings": findings}, name)
    return json.loads(Path(out).read_text())


def _violations(doc: dict) -> list[str]:
    errors = jsonschema.Draft4Validator(_SCHEMA).iter_errors(doc)
    return [f"{'/'.join(str(p) for p in e.path) or '(root)'}: {e.message}" for e in errors]


def _github_violations(doc: dict) -> list[str]:
    """Constraints GitHub code scanning enforces on top of the schema.

    These exist because schema conformance is not the bar that matters. An
    earlier export validated with zero schema errors and was rejected outright
    on upload — zero results ingested, the CI gate silently inert. Both causes
    are encoded here:

      * ``network://host:port`` locations → "SARIF URI scheme 'network' did not
        match the checkout URI scheme 'file'". Every location is resolved
        against the checked-out repo, so any scheme at all is fatal.
      * evidence in a ``relatedLocations`` entry with no physicalLocation →
        "buildRelatedLocations:expected physical location".
    """
    problems: list[str] = []
    for run_i, run in enumerate(doc.get("runs", [])):
        for base_id, base in (run.get("originalUriBaseIds") or {}).items():
            if "://" in str(base.get("uri", "")):
                problems.append(f"runs/{run_i}: uriBase {base_id} has a URI scheme: {base['uri']}")
        for res_i, result in enumerate(run.get("results", [])):
            where = f"runs/{run_i}/results/{res_i}"
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation")
                if not phys:
                    problems.append(f"{where}: location without physicalLocation")
                    continue
                uri = str((phys.get("artifactLocation") or {}).get("uri", ""))
                if not uri:
                    problems.append(f"{where}: physicalLocation without a uri")
                elif "://" in uri or uri.startswith("/"):
                    problems.append(f"{where}: location uri is not repo-relative: {uri}")
            for rel_i, rel in enumerate(result.get("relatedLocations", [])):
                if not rel.get("physicalLocation"):
                    problems.append(f"{where}/relatedLocations/{rel_i}: no physicalLocation")
    return problems


# ── schema conformance ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_typical_scan_validates(tmp_path):
    doc = await _render(tmp_path, [finding()])
    assert _violations(doc) == []


@pytest.mark.asyncio
async def test_scan_without_timestamps_validates(tmp_path):
    """Regression: a pending or running scan has no start/finish time, and
    emitting null for them produced a document that uploads rejected."""
    doc = await _render(
        tmp_path, [finding()], sc=scan(status="running", started_at=None, finished_at=None)
    )
    assert _violations(doc) == []
    invocation = doc["runs"][0]["invocations"][0]
    assert "startTimeUtc" not in invocation
    assert "endTimeUtc" not in invocation
    assert invocation["executionSuccessful"] is False


@pytest.mark.asyncio
async def test_scan_with_no_findings_validates(tmp_path):
    doc = await _render(tmp_path, [])
    assert _violations(doc) == []
    assert doc["runs"][0]["results"] == []


@pytest.mark.asyncio
async def test_sparse_finding_validates(tmp_path):
    """Every optional field absent at once — the shape an info-level finding
    with no port, evidence, remediation or CVSS actually takes."""
    doc = await _render(tmp_path, [finding(
        plugin_id="web.http_headers", severity="info", title="Missing HSTS",
        description=None, remediation=None, evidence=None,
        cvss_score=None, port_number=None, host_ip="",
    )])
    assert _violations(doc) == []


@pytest.mark.asyncio
async def test_finding_with_cves_validates(tmp_path):
    doc = await _render(tmp_path, [finding(
        plugin_id="cve.cve_matcher", severity="critical",
        title="Log4Shell", cve_ids=json.dumps(["CVE-2021-44228", "CVE-2021-45046"]),
    )])
    assert _violations(doc) == []


@pytest.mark.asyncio
async def test_malformed_cve_json_does_not_break_the_export(tmp_path):
    doc = await _render(tmp_path, [finding(cve_ids="not json at all")])
    assert _violations(doc) == []


@pytest.mark.asyncio
async def test_naive_timestamps_render_as_utc(tmp_path):
    """isoformat gives '+00:00' where SARIF's dateTime pattern wants 'Z'."""
    doc = await _render(tmp_path, [finding()], sc=scan(
        started_at=datetime(2026, 3, 1, 12, 0, 0),  # naive
        finished_at=datetime(2026, 3, 1, 12, 5, 0, tzinfo=timezone.utc),
    ))
    assert _violations(doc) == []
    inv = doc["runs"][0]["invocations"][0]
    assert inv["startTimeUtc"].endswith("Z")
    assert inv["endTimeUtc"].endswith("Z")


# ── consumer interop ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_locations_are_repo_relative_for_github(tmp_path):
    """Regression: network:// locations passed schema validation and were
    rejected on upload, ingesting zero results."""
    doc = await _render(tmp_path, [finding(), finding(port_number=None, host_ip="")])
    assert _github_violations(doc) == []
    for result in doc["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "://" not in uri
        assert not uri.startswith("/")
        assert "uriBaseId" not in result["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "originalUriBaseIds" not in doc["runs"][0]


@pytest.mark.asyncio
async def test_the_network_address_survives_in_logical_locations(tmp_path):
    """The physical path is synthetic, so this is the only place the real
    host/port is machine-readable. Losing it would make the export useless to
    anything that understands network results."""
    doc = await _render(tmp_path, [finding()])
    logical = doc["runs"][0]["results"][0]["locations"][0]["logicalLocations"]
    assert {"name": "192.0.2.10", "kind": "networkHost"} in logical
    assert {"name": "21", "kind": "networkPort"} in logical


@pytest.mark.asyncio
async def test_evidence_is_carried_without_a_bare_related_location(tmp_path):
    """Regression: evidence in a relatedLocations entry with no physicalLocation
    made GitHub reject the whole document."""
    doc = await _render(tmp_path, [finding(evidence="230 Login successful.")])
    assert _github_violations(doc) == []
    result = doc["runs"][0]["results"][0]
    assert "relatedLocations" not in result
    assert "230 Login successful." in result["message"]["text"]
    assert result["properties"]["evidence"] == "230 Login successful."


@pytest.mark.asyncio
async def test_every_rendered_shape_would_upload(tmp_path):
    """Run the GitHub constraints over the same shapes the schema tests cover —
    the point being that schema-clean and upload-clean are different bars."""
    for findings in (
        [finding()],
        [],
        [finding(evidence=None, port_number=None, host_ip="", description=None)],
        [finding(cve_ids=json.dumps(["CVE-2021-44228"]))],
        [finding(validated=True, validation_method="browser-dialog")],
        [finding(false_positive=True, analyst_notes="dismissed")],
    ):
        doc = await _render(tmp_path, findings)
        assert _violations(doc) == [], findings
        assert _github_violations(doc) == [], findings


@pytest.mark.asyncio
async def test_cve_links_are_reachable_from_the_rule(tmp_path):
    """They used to sit in a `relationships` entry pointing at a toolComponent
    that was never declared, so nothing could resolve them."""
    doc = await _render(tmp_path, [finding(
        plugin_id="cve.cve_matcher", cve_ids=json.dumps(["CVE-2021-44228"]),
    )])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "CVE-2021-44228" in rule["help"]["markdown"]
    assert rule["helpUri"].startswith("https://nvd.nist.gov/")
    assert "relationships" not in rule


@pytest.mark.asyncio
async def test_every_result_carries_a_fingerprint(tmp_path):
    doc = await _render(tmp_path, [finding(), finding(port_number=22, title="Other")])
    for r in doc["runs"][0]["results"]:
        assert r["partialFingerprints"]["scanrFindingV1"]


@pytest.mark.asyncio
async def test_every_result_references_a_declared_rule(tmp_path):
    """A ruleId with no matching rule breaks the alert description in consumers."""
    doc = await _render(tmp_path, [
        finding(),
        finding(plugin_id="web.http_headers", title="Missing HSTS"),
        finding(),  # duplicate plugin — must not produce a duplicate rule
    ])
    run = doc["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids)), "duplicate rule definitions"
    for result in run["results"]:
        assert result["ruleId"] in rule_ids


# ── fingerprint stability ────────────────────────────────────────────────────

def test_fingerprint_is_stable_across_runs():
    a = _fingerprint("services.ftp_anon", "192.0.2.10", 21, "Anonymous FTP login allowed")
    b = _fingerprint("services.ftp_anon", "192.0.2.10", 21, "Anonymous FTP login allowed")
    assert a == b


def test_fingerprint_distinguishes_host_port_and_plugin():
    base = ("services.ftp_anon", "192.0.2.10", 21, "Anonymous FTP login allowed")
    variants = [
        ("services.ssh_default_creds", "192.0.2.10", 21, "Anonymous FTP login allowed"),
        ("services.ftp_anon", "192.0.2.11", 21, "Anonymous FTP login allowed"),
        ("services.ftp_anon", "192.0.2.10", 2121, "Anonymous FTP login allowed"),
        ("services.ftp_anon", "192.0.2.10", 21, "A different finding"),
    ]
    assert len({_fingerprint(*v) for v in [base, *variants]}) == 5


def test_fingerprint_ignores_re_rating_and_changed_evidence():
    """A finding whose CVSS is re-rated, or whose banner shifts between runs, is
    still the same finding — otherwise remediation history breaks on every scan."""
    assert _fingerprint("p", "192.0.2.10", 21, "t") == _fingerprint("p", "192.0.2.10", 21, "t")


def test_fingerprint_handles_a_missing_port():
    assert _fingerprint("p", "192.0.2.10", None, "t") != _fingerprint("p", "192.0.2.10", 0, "t")


def test_report_formats_match_the_engine_dispatch():
    """A format the API accepts but the engine cannot render would queue a job
    that can only fail; one the engine handles but the API rejects is dead code."""
    import re
    from pathlib import Path
    from typing import get_args

    from scanr.schemas.report import ReportFormat

    engine = (Path(__file__).resolve().parents[2] / "scanr" / "reporting" / "report_engine.py").read_text()
    dispatch = set(re.findall(r'^\s+case "([a-z]+)":', engine, re.M))
    assert dispatch, "could not parse the engine dispatch — the test is broken"
    assert set(get_args(ReportFormat)) == dispatch


# ── validated findings ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_validated_finding_is_tagged_and_still_schema_valid(tmp_path):
    """The tag is what makes proof visible in GitHub code scanning, where the
    property bag is not shown but tags are."""
    doc = await _render(tmp_path, [
        finding(validated=True, validation_method="browser-dialog"),
        finding(title="Unproven", validated=False),
    ])
    assert _violations(doc) == []
    proved, unproven = doc["runs"][0]["results"]
    assert proved["properties"]["validated"] is True
    assert proved["properties"]["tags"] == ["validated"]
    assert proved["properties"]["validation_method"] == "browser-dialog"
    assert unproven["properties"]["validated"] is False
    assert "tags" not in unproven["properties"], "only proof gets the badge"
