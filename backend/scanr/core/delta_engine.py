"""
Scan comparison / delta engine.
Computes differences between two scans: new/resolved/persisting findings,
new/removed hosts, port changes.
"""
from __future__ import annotations

import json
import re
from hashlib import sha1

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanr.models import Finding, Host, Port


def _finding_key(f: Finding, host_ip_map: dict[str, str]) -> str:
    """Canonical key for deduplication across scans."""
    ip = host_ip_map.get(f.host_id or "", "")
    if f.plugin_id in {"network.subdomain_enum", "network.dns_recon", "network.dns_zone_transfer"}:
        digest = sha1((f.evidence or "").encode("utf-8")).hexdigest()[:16]
        return f"{f.plugin_id}|{ip}|{f.title}|{digest}"
    return f"{f.plugin_id}|{ip}|{f.port_number or ''}|{f.title}"


def _serialize_finding(f: Finding, host_ip_map: dict[str, str]) -> dict:
    return {
        "id": f.id,
        "plugin_id": f.plugin_id,
        "severity": f.severity,
        "title": f.title,
        "host_ip": host_ip_map.get(f.host_id or "", ""),
        "port_number": f.port_number,
        "cvss_score": f.cvss_score,
        "compliance_tags": json.loads(f.compliance_tags) if f.compliance_tags else [],
    }


def _serialize_host(h: Host) -> dict:
    return {"id": h.id, "ip": h.ip, "hostname": h.hostname, "os_fingerprint": h.os_fingerprint}


def _subdomains_from_findings(findings: list[Finding]) -> set[str]:
    names: set[str] = set()
    for finding in findings:
        if finding.plugin_id != "network.subdomain_enum":
            continue
        for line in (finding.evidence or "").splitlines():
            match = re.match(r"\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*[→-]", line)
            if match:
                names.add(match.group(1).lower())
    return names


async def _load_scan_data(scan_id: str, db: AsyncSession):
    host_result = await db.execute(
        select(Host).where(Host.scan_id == scan_id).options(selectinload(Host.ports))
    )
    hosts = host_result.scalars().all()

    finding_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = finding_result.scalars().all()

    host_ip_map = {h.id: h.ip for h in hosts}
    return hosts, findings, host_ip_map


async def compute_delta(baseline_scan_id: str, new_scan_id: str, db: AsyncSession) -> dict:
    """
    Returns delta dict comparing new_scan vs baseline_scan.
    """
    baseline_hosts, baseline_findings, baseline_ip_map = await _load_scan_data(baseline_scan_id, db)
    new_hosts, new_findings, new_ip_map = await _load_scan_data(new_scan_id, db)

    # Host sets
    baseline_ips = {h.ip for h in baseline_hosts}
    new_ips = {h.ip for h in new_hosts}
    new_host_ips = new_ips - baseline_ips
    removed_host_ips = baseline_ips - new_ips

    new_hosts_out = [_serialize_host(h) for h in new_hosts if h.ip in new_host_ips]
    removed_hosts_out = [_serialize_host(h) for h in baseline_hosts if h.ip in removed_host_ips]

    # Port changes per host (for hosts in both scans)
    port_changes = []
    baseline_host_map = {h.ip: h for h in baseline_hosts}
    new_host_map = {h.ip: h for h in new_hosts}
    for ip in baseline_ips & new_ips:
        bh = baseline_host_map[ip]
        nh = new_host_map[ip]
        b_ports = {(p.number, p.protocol) for p in bh.ports}
        n_ports = {(p.number, p.protocol) for p in nh.ports}
        opened = n_ports - b_ports
        closed = b_ports - n_ports
        if opened or closed:
            port_changes.append({
                "ip": ip,
                "opened": [{"port": p, "protocol": q} for p, q in sorted(opened)],
                "closed": [{"port": p, "protocol": q} for p, q in sorted(closed)],
            })

    # Finding sets
    baseline_keys = {_finding_key(f, baseline_ip_map): f for f in baseline_findings}
    new_keys = {_finding_key(f, new_ip_map): f for f in new_findings}

    new_finding_keys = set(new_keys) - set(baseline_keys)
    resolved_keys = set(baseline_keys) - set(new_keys)
    persisting_keys = set(new_keys) & set(baseline_keys)

    baseline_subdomains = _subdomains_from_findings(baseline_findings)
    current_subdomains = _subdomains_from_findings(new_findings)
    new_subdomains = sorted(current_subdomains - baseline_subdomains)
    removed_subdomains = sorted(baseline_subdomains - current_subdomains)

    return {
        "baseline_scan_id": baseline_scan_id,
        "new_scan_id": new_scan_id,
        "summary": {
            "new_findings": len(new_finding_keys),
            "resolved_findings": len(resolved_keys),
            "persisting_findings": len(persisting_keys),
            "new_hosts": len(new_hosts_out),
            "removed_hosts": len(removed_hosts_out),
            "port_changes": len(port_changes),
            "new_subdomains": len(new_subdomains),
            "removed_subdomains": len(removed_subdomains),
        },
        "new_findings": [_serialize_finding(new_keys[k], new_ip_map) for k in new_finding_keys],
        "resolved_findings": [_serialize_finding(baseline_keys[k], baseline_ip_map) for k in resolved_keys],
        "persisting_findings": [_serialize_finding(new_keys[k], new_ip_map) for k in persisting_keys],
        "new_hosts": new_hosts_out,
        "removed_hosts": removed_hosts_out,
        "new_subdomains": new_subdomains,
        "removed_subdomains": removed_subdomains,
        "port_changes": port_changes,
    }
