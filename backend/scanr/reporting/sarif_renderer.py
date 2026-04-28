"""SARIF 2.1.0 report renderer.

SARIF (Static Analysis Results Interchange Format) is consumed natively by
DefectDojo, GitHub Advanced Security, Azure DevOps Security, and most modern
DevSecOps pipelines. This renderer maps ScanR findings to SARIF results.

Mapping:
  ScanR Plugin    → SARIF Rule
  ScanR Finding   → SARIF Result
  CVSS severity   → SARIF level (error/warning/note/none)
  host_ip:port    → SARIF physicalLocation (artifactLocation uri)
"""
from __future__ import annotations

import json
from pathlib import Path

import aiofiles

from scanr.config import get_settings

settings = get_settings()

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecificationDraft01/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEV_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

_SEV_TO_SCORE = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}


async def render_sarif(context: dict, report_id: str) -> Path:
    scan = context["scan"]
    findings = context["findings"]

    # Build rules from unique plugin IDs
    seen_plugins: set[str] = set()
    rules = []
    for f in findings:
        if f.plugin_id not in seen_plugins:
            seen_plugins.add(f.plugin_id)
            cve_refs = []
            if f.cve_ids:
                try:
                    cve_list = json.loads(f.cve_ids) if isinstance(f.cve_ids, str) else f.cve_ids
                    for cve in cve_list:
                        cve_refs.append({"text": cve, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"})
                except Exception:
                    pass

            rule = {
                "id": f.plugin_id,
                "name": f.plugin_id.replace(".", "_").replace("-", "_"),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "defaultConfiguration": {"level": _SEV_TO_LEVEL.get(f.severity, "warning")},
                "properties": {
                    "severity": f.severity,
                    "tags": ["security", "scanr"],
                },
            }
            if f.remediation:
                rule["help"] = {"text": f.remediation, "markdown": f.remediation}
            if cve_refs:
                rule["relationships"] = [
                    {"target": {"id": ref["text"], "toolComponent": {"name": "NVD"}}, "kinds": ["relevant"]}
                    for ref in cve_refs
                ]
            rules.append(rule)

    # Build results
    results = []
    for f in findings:
        host_ip = getattr(f, "host_ip", "") or ""
        uri = f"network://{host_ip}:{f.port_number}" if host_ip and f.port_number else f"network://{host_ip}"

        result: dict = {
            "ruleId": f.plugin_id,
            "level": _SEV_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.description or f.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%NETWORK%"},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [
                        {"name": host_ip, "kind": "networkHost"},
                        *(
                            [{"name": str(f.port_number), "kind": "networkPort"}]
                            if f.port_number else []
                        ),
                    ],
                }
            ],
            "properties": {
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "false_positive": f.false_positive,
                "remediation_status": f.remediation_status,
            },
        }
        if f.analyst_notes:
            result["suppressions"] = [{"kind": "inSource", "justification": f.analyst_notes}] if f.false_positive else []
            result["properties"]["analyst_notes"] = f.analyst_notes

        if f.evidence:
            result["relatedLocations"] = [
                {"id": 1, "message": {"text": f.evidence[:2000]}}
            ]

        results.append(result)

    sarif_doc = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ScanR",
                        "version": settings.app_version,
                        "informationUri": "https://github.com/T3rr0or/ScanR",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": scan.status == "completed",
                        "startTimeUtc": scan.started_at.isoformat() if scan.started_at else None,
                        "endTimeUtc": scan.finished_at.isoformat() if scan.finished_at else None,
                    }
                ],
                "properties": {
                    "scanName": scan.name,
                    "scanId": scan.id,
                    "hostsScanned": scan.hosts_up,
                },
            }
        ],
    }

    out = settings.reports_dir / f"{report_id}.sarif"
    async with aiofiles.open(out, "w") as fp:
        await fp.write(json.dumps(sarif_doc, indent=2, default=str))
    return out
