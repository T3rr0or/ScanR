from __future__ import annotations

import json
from pathlib import Path

import aiofiles

from scanr.config import get_settings

settings = get_settings()


async def render_json(context: dict, report_id: str) -> Path:
    scan = context["scan"]
    findings = context["findings"]
    hosts = context["hosts"]

    data = {
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "status": scan.status,
            "profile": scan.profile,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "hosts_total": scan.hosts_total,
            "hosts_up": scan.hosts_up,
        },
        "hosts": [
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "os_name": h.os_name,
                "status": h.status,
                "ports": [
                    {
                        "number": p.number,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": {
                            "name": p.service.name,
                            "product": p.service.product,
                            "version": p.service.version,
                        } if p.service else None,
                    }
                    for p in h.ports
                ],
            }
            for h in hosts
        ],
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "host_ip": getattr(f, "host_ip", ""),
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "cve_ids": json.loads(f.cve_ids) if f.cve_ids else [],
                "plugin_id": f.plugin_id,
                "port_number": f.port_number,
                "protocol": f.protocol,
                "false_positive": f.false_positive,
                "remediation_status": f.remediation_status,
                "analyst_notes": f.analyst_notes,
            }
            for f in findings
        ],
        "summary": {
            "critical": len(context["findings_by_severity"].get("critical", [])),  # was returning list, not count
            "high": len(context["findings_by_severity"].get("high", [])),
            "medium": len(context["findings_by_severity"].get("medium", [])),
            "low": len(context["findings_by_severity"].get("low", [])),
            "info": len(context["findings_by_severity"].get("info", [])),
        },
    }

    out = settings.reports_dir / f"{report_id}.json"
    async with aiofiles.open(out, "w") as f:
        await f.write(json.dumps(data, indent=2, default=str))
    return out
