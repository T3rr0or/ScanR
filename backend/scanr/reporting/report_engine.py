from __future__ import annotations

import base64
import logging
from collections import defaultdict
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanr.config import get_settings
from scanr.models import Finding, Host, Report, Scan, Screenshot, Target

logger = logging.getLogger(__name__)
settings = get_settings()

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate(self, report: Report) -> Path:
        # Load scan with all relations
        result = await self.db.execute(
            select(Scan)
            .where(Scan.id == report.scan_id)
            .options(selectinload(Scan.targets))
        )
        scan = result.scalar_one()

        hosts_result = await self.db.execute(
            select(Host)
            .where(Host.scan_id == scan.id)
            .options(selectinload(Host.ports))
        )
        hosts = hosts_result.scalars().all()

        findings_result = await self.db.execute(
            select(Finding)
            .where(Finding.scan_id == scan.id, Finding.false_positive == False)
            .order_by(Finding.severity)
        )
        findings = findings_result.scalars().all()

        # Enrich findings with host_ip (avoids extra joins in template)
        ip_map = {h.id: h.ip for h in hosts}
        for f in findings:
            f.host_ip = ip_map.get(f.host_id) or ""  # type: ignore[attr-defined]

        # Load ALL screenshots (even those without a saved file — shown as error entries)
        screenshots_result = await self.db.execute(
            select(Screenshot)
            .where(Screenshot.scan_id == scan.id)
            .order_by(Screenshot.url)
        )
        raw_shots = screenshots_result.scalars().all()
        screenshots = [_enrich_screenshot(s) for s in raw_shots]

        from scanr.reporting.executive_summary import generate_summary
        exec_summary = generate_summary(scan, hosts, findings)

        context = {
            "scan": scan,
            "hosts": hosts,
            "findings": findings,
            "findings_by_severity": self._group_by_severity(findings),
            "findings_by_plugin": self._group_by_plugin(findings),
            "total_findings": len(findings),
            "screenshots": screenshots,
            "executive_summary": exec_summary,
        }

        settings.reports_dir.mkdir(parents=True, exist_ok=True)
        report_id = report.id

        match report.format:
            case "html":
                from scanr.reporting.html_renderer import render_html
                out = await render_html(context, report_id)
            case "pdf":
                from scanr.reporting.pdf_renderer import render_pdf
                out = await render_pdf(context, report_id)
            case "json":
                from scanr.reporting.json_renderer import render_json
                out = await render_json(context, report_id)
            case "csv":
                from scanr.reporting.csv_renderer import render_csv
                out = await render_csv(context, report_id)
            case _:
                raise ValueError(f"Unknown report format: {report.format}")

        logger.info("Report %s generated: %s", report_id, out)
        return out

    def _group_by_severity(self, findings) -> dict:
        groups: dict[str, list] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for f in findings:
            groups.setdefault(f.severity, []).append(f)
        return groups

    def _group_by_plugin(self, findings) -> list[dict]:
        """Group findings by plugin_id so repeated findings (dir brute-force, open ports, etc.)
        collapse into a single entry with a compact instance table."""
        buckets: dict[str, list] = defaultdict(list)
        for f in findings:
            buckets[f.plugin_id].append(f)

        groups = []
        for plugin_id, grp in buckets.items():
            # Representative finding: highest severity in the group
            rep = min(grp, key=lambda f: _SEV_ORDER.get(f.severity, 99))

            # Shared description/remediation (show once if all instances have the same value)
            all_desc = {f.description for f in grp}
            all_rem = {f.remediation for f in grp}
            shared_description = rep.description if len(all_desc) == 1 else None
            shared_remediation = next((r for r in all_rem if r), None)

            # CVE / compliance tags from the representative finding
            groups.append({
                "plugin_id": plugin_id,
                "severity": rep.severity,
                "title": rep.title if len(grp) == 1 else _plugin_label(plugin_id, grp),
                "count": len(grp),
                "findings": sorted(grp, key=lambda f: (f.host_ip, f.port_number or 0)),  # type: ignore[attr-defined]
                "description": shared_description,
                "remediation": shared_remediation,
                "cve_ids": rep.cve_ids,
                "cvss_score": rep.cvss_score,
                "compliance_tags": rep.compliance_tags,
                "mitre_tags": rep.mitre_tags,
            })

        # Sort: severity first, then plugin_id alphabetically
        groups.sort(key=lambda g: (_SEV_ORDER.get(g["severity"], 99), g["plugin_id"]))
        return groups


def _plugin_label(plugin_id: str, findings: list) -> str:
    """Return a concise group title for multi-instance findings."""
    # Use a human-readable name based on plugin_id
    _LABELS = {
        "network.open_ports_info": "Open Ports",
        "web.dir_bruteforce": "Directory / Path Discovery",
        "web.http_headers": "Missing Security Headers",
        "web.sensitive_files": "Sensitive File Exposure",
        "web.cors_misconfig": "CORS Misconfiguration",
        "web.clickjacking": "Clickjacking Protection Missing",
        "web.http_methods": "Dangerous HTTP Methods Enabled",
        "web.dir_listing": "Directory Listing Enabled",
        "web.open_redirect": "Open Redirect",
        "web.path_traversal": "Path Traversal / LFI",
        "web.graphql_introspection": "GraphQL Introspection Enabled",
        "ssl_tls.cert_inspector": "SSL Certificate Issues",
        "ssl_tls.cipher_audit": "Weak Cipher Suites",
        "ssl_tls.protocol_check": "Deprecated TLS/SSL Protocols",
        "services.ftp_anon": "FTP Anonymous Access",
        "services.smtp_open_relay": "SMTP Open Relay",
        "services.snmp_community": "SNMP Default Community Strings",
        "services.telnet_detect": "Telnet Service Detected",
        "services.vnc_auth": "VNC Authentication Weakness",
        "ssh.ssh_algos": "Weak SSH Algorithms",
        "ssh.ssh_version": "Vulnerable SSH Version",
        "cve.cve_matcher": "CVE Version Matches",
    }
    label = _LABELS.get(plugin_id)
    if label:
        return f"{label} ({len(findings)} instances)"
    # Fallback: prettify the plugin_id
    _, _, name = plugin_id.rpartition(".")
    return f"{name.replace('_', ' ').title()} ({len(findings)} instances)"


def _enrich_screenshot(shot: Screenshot) -> dict:
    """Return screenshot fields + inline base64 data URI for the image."""
    data_uri = None
    if shot.file_path:
        try:
            img_bytes = Path(shot.file_path).read_bytes()
            data_uri = "data:image/png;base64," + base64.b64encode(img_bytes).decode()
        except Exception:
            pass
    return {
        "id": shot.id,
        "url": shot.url,
        "title": shot.title or shot.url,
        "status_code": shot.status_code,
        "content_type": shot.content_type,
        "data_uri": data_uri,
        "error": shot.error,
    }
