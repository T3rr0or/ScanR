"""Auto-generate a plain-English executive summary for a scan report."""
from __future__ import annotations

from datetime import datetime, timezone
import html as _html


def _esc(text: str | None) -> str:
    return _html.escape(text or "")


def generate_summary(scan, hosts: list, findings: list) -> str:
    """
    Returns an HTML string for the executive summary section.
    Uses only scan metadata, hosts, and findings — no LLM required.
    """
    total_hosts = len(hosts)
    hosts_up = sum(1 for h in hosts if getattr(h, "status", "") == "up")
    target_count = getattr(scan, "hosts_total", total_hosts)

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = getattr(f, "severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_findings = len(findings)
    critical = severity_counts["critical"]
    high = severity_counts["high"]
    medium = severity_counts["medium"]

    # Date formatting
    finished = getattr(scan, "finished_at", None)
    date_str = finished.strftime("%B %d, %Y") if finished else datetime.now(timezone.utc).strftime("%B %d, %Y")

    # Duration
    started = getattr(scan, "started_at", None)
    duration_str = ""
    if started and finished:
        secs = int((finished - started).total_seconds())
        if secs < 60:
            duration_str = f" in {secs} seconds"
        elif secs < 3600:
            duration_str = f" in {secs // 60}m {secs % 60}s"
        else:
            duration_str = f" in {secs // 3600}h {(secs % 3600) // 60}m"

    scan_name = _esc(getattr(scan, "name", "Unknown Scan"))

    # Risk level
    if critical > 0:
        risk_level = "CRITICAL"
        risk_color = "#dc2626"
        risk_desc = "requires immediate remediation"
    elif high > 0:
        risk_level = "HIGH"
        risk_color = "#ea580c"
        risk_desc = "requires prompt remediation"
    elif medium > 0:
        risk_level = "MEDIUM"
        risk_color = "#d97706"
        risk_desc = "warrants planned remediation"
    else:
        risk_level = "LOW"
        risk_color = "#16a34a"
        risk_desc = "no critical or high-severity issues identified"

    # Top findings
    critical_findings = [f for f in findings if getattr(f, "severity", "") == "critical"]
    high_findings = [f for f in findings if getattr(f, "severity", "") == "high"]
    top_findings = (critical_findings + high_findings)[:3]
    top_titles = [f"<li>{_esc(getattr(f, 'title', 'Unknown'))}</li>" for f in top_findings]
    top_list = f"<ul>{''.join(top_titles)}</ul>" if top_titles else ""

    # Findings breakdown sentence
    parts = []
    if critical:
        parts.append(f"<strong style='color:#dc2626'>{critical} critical</strong>")
    if high:
        parts.append(f"<strong style='color:#ea580c'>{high} high</strong>")
    if medium:
        parts.append(f"<strong style='color:#d97706'>{medium} medium</strong>")
    remaining = total_findings - critical - high - medium
    if remaining > 0:
        parts.append(f"{remaining} lower-severity")

    breakdown = ", ".join(parts) if parts else "no significant"

    return f"""
<div style="background:#f8fafc;border-left:4px solid {risk_color};padding:1.5rem;margin-bottom:2rem;border-radius:4px;">
  <h2 style="margin:0 0 0.5rem 0;font-size:1.25rem;color:#0f172a;">Executive Summary</h2>
  <p style="margin:0.5rem 0;color:#374151;line-height:1.6;">
    The assessment of <strong>{scan_name}</strong> completed on {date_str}{duration_str},
    evaluating {target_count} target(s) with {hosts_up} host(s) responding.
    A total of <strong>{total_findings} finding(s)</strong> were identified: {breakdown}.
  </p>
  <p style="margin:0.5rem 0;color:#374151;line-height:1.6;">
    Overall risk rating:
    <span style="font-weight:bold;color:{risk_color};">{risk_level}</span>
    — {risk_desc}.
  </p>
  {f'<p style="margin:0.5rem 0;color:#374151;"><strong>Priority items requiring attention:</strong>{top_list}</p>' if top_list else ''}
</div>
""".strip()
