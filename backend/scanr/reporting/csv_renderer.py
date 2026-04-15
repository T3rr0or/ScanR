from __future__ import annotations

import csv
import io
from pathlib import Path

import aiofiles

from scanr.config import get_settings

settings = get_settings()


async def render_csv(context: dict, report_id: str) -> Path:
    findings = context["findings"]
    out = settings.reports_dir / f"{report_id}.csv"

    rows = []
    for f in findings:
        rows.append({
            "severity": f.severity,
            "title": f.title,
            "plugin_id": f.plugin_id,
            "cvss_score": f.cvss_score or "",
            "cve_ids": f.cve_ids or "",
            "port": f"{f.port_number}/{f.protocol}" if f.port_number else "",
            "description": (f.description or "").replace("\n", " "),
            "remediation": (f.remediation or "").replace("\n", " "),
            "evidence": (f.evidence or "")[:200].replace("\n", " "),
        })

    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    async with aiofiles.open(out, "w") as f:
        await f.write(buf.getvalue())
    return out
