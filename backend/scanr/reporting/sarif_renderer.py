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

import hashlib
import json
from pathlib import Path

import aiofiles

from scanr.config import get_settings

settings = get_settings()

#: Identifier for the artifactLocation.uriBaseId used below. Declared in
#: originalUriBaseIds so the reference resolves — a uriBaseId that names nothing
#: is schema-valid but leaves consumers unable to interpret the location.
_URI_BASE_ID = "NETWORK"

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


def _utc(value) -> str:
    """SARIF requires RFC 3339 with a 'Z' offset for *TimeUtc fields.

    Naive datetimes are assumed UTC — that is what the scanner stores — and
    Python's isoformat renders '+00:00' where SARIF's dateTime pattern wants 'Z'.
    """
    from datetime import timezone

    if getattr(value, "tzinfo", None) is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat(timespec="milliseconds") + "Z"


def _fingerprint(plugin_id: str, host_ip: str, port: int | None, title: str) -> str:
    """Stable identity for a finding across scans.

    Consumers (GitHub code scanning, DefectDojo) use partialFingerprints to tell
    "the same issue, seen again" from "a new issue". Without it, every re-scan
    looks like a fresh set of alerts and the remediation history is lost — the
    same correlation ScanR's own delta engine does internally, exposed so external
    tools can do it too.

    Deliberately excludes severity and evidence: a finding whose CVSS is re-rated,
    or whose banner text shifts between runs, is still the same finding.
    """
    parts = f"{plugin_id}|{host_ip}|{port if port is not None else ''}|{title}"
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()[:32]


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
            help_text = f.remediation or ""
            if cve_refs:
                # Rendered as links rather than SARIF `relationships`: a
                # relationship must point at a toolComponent declared in this run
                # (an extension or taxonomy), and "NVD" is neither — the reference
                # dangled, so consumers had nothing to resolve it against. A
                # helpUri plus markdown links is what they actually surface.
                links = "\n".join(f"- [{r['text']}]({r['url']})" for r in cve_refs)
                help_text = (help_text + "\n\nReferences:\n" + links).strip()
                rule["helpUri"] = cve_refs[0]["url"]
                rule["properties"]["cve_ids"] = [r["text"] for r in cve_refs]
            if help_text:
                rule["help"] = {"text": help_text, "markdown": help_text}
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
            # Lets consumers recognise the same finding across re-scans instead of
            # treating every run as a fresh set of alerts.
            "partialFingerprints": {
                "scanrFindingV1": _fingerprint(f.plugin_id, host_ip, f.port_number, f.title),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": _URI_BASE_ID},
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
                "validated": bool(getattr(f, "validated", False)),
            },
        }
        # A reproduced finding is worth surfacing where a triager will see it —
        # in GitHub code scanning the tag lands on the alert itself.
        if getattr(f, "validated", False):
            result["properties"]["tags"] = ["validated"]
            result["properties"]["validation_method"] = f.validation_method
        if f.analyst_notes:
            result["suppressions"] = [{"kind": "inSource", "justification": f.analyst_notes}] if f.false_positive else []
            result["properties"]["analyst_notes"] = f.analyst_notes

        if f.evidence:
            result["relatedLocations"] = [
                {"id": 1, "message": {"text": f.evidence[:2000]}}
            ]

        results.append(result)

    # Omit absent timestamps rather than emitting null: SARIF types these as
    # strings, so a scan that has not started or finished (exported while pending
    # or running) produced a document that fails schema validation and is rejected
    # on upload.
    invocation: dict = {"executionSuccessful": scan.status == "completed"}
    if scan.started_at:
        invocation["startTimeUtc"] = _utc(scan.started_at)
    if scan.finished_at:
        invocation["endTimeUtc"] = _utc(scan.finished_at)

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
                # Declares the base that result locations are relative to, so the
                # uriBaseId on each artifactLocation resolves to something.
                "originalUriBaseIds": {
                    _URI_BASE_ID: {
                        "uri": "network://",
                        "description": {
                            "text": "Network locations, addressed as network://<host>[:<port>]."
                        },
                    }
                },
                "invocations": [invocation],
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
