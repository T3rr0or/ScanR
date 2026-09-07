from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanr.reporting.csv_safety import spreadsheet_safe_cell


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=HYPERLINK(\"https://attacker.invalid\")", "'=HYPERLINK(\"https://attacker.invalid\")"),
        ("+cmd|' /C calc'!A0", "'+cmd|' /C calc'!A0"),
        ("-2+3", "'-2+3"),
        ("@SUM(1,1)", "'@SUM(1,1)"),
        ("  =1+1", "'  =1+1"),
        ("\t=1+1", "'\t=1+1"),
        ("\v=1+1", "'\v=1+1"),
        ("ordinary text", "ordinary text"),
        ("'already-text", "'already-text"),
        (42, 42),
        (None, None),
    ],
)
def test_spreadsheet_safe_cell(value: object, expected: object) -> None:
    assert spreadsheet_safe_cell(value) == expected


@pytest.mark.asyncio
async def test_report_renderer_sanitizes_every_untrusted_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scanr.reporting import csv_renderer

    monkeypatch.setattr(csv_renderer.settings, "reports_dir", tmp_path)
    finding = SimpleNamespace(
        severity="high",
        title="=WEBSERVICE(\"https://attacker.invalid\")",
        host_ip="@malicious",
        plugin_id="safe.plugin",
        cvss_score=8.1,
        cve_ids="",
        port_number=443,
        protocol="tcp",
        remediation_status="open",
        false_positive=False,
        analyst_notes="  +cmd",
        description="normal",
        remediation="normal",
        evidence="\t=1+1",
    )

    output = await csv_renderer.render_csv({"findings": [finding]}, "formula-test")
    with output.open(newline="") as handle:
        row = next(csv.DictReader(handle))

    assert row["title"].startswith("'=")
    assert row["host_ip"].startswith("'@")
    assert row["analyst_notes"].startswith("'  +")
    assert row["evidence"].startswith("'\t=")
