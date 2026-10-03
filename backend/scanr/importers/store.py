"""Write a parsed import into a scan: hosts, open ports, services and findings.

Imported findings are attached to hosts and ports like native ones, so assets,
fix-first priority, trends, retest scoping and reports all treat them the same.
Re-importing the same report into a scan adds nothing twice.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.importers.parsers import ImportResult
from scanr.models import Finding, Host, Port, Scan
from scanr.models.base import new_uuid
from scanr.models.service import Service

IMPORTED_PROFILE = "imported"
_SEVERITY_COLUMNS = ("critical", "high", "medium", "low", "info")


@dataclass
class ImportSummary:
    source: str
    hosts_added: int = 0
    ports_added: int = 0
    findings_added: int = 0
    duplicates_skipped: int = 0


def _host_key(address: str) -> str:
    """IPs are stored as-is; a bare hostname (Burp, Nuclei without -ip) is kept
    in the ip column too, truncated to fit, so the finding still has a host."""
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return address.lower()[:45]


async def store(db: AsyncSession, scan: Scan, result: ImportResult, user_id: str) -> ImportSummary:
    summary = ImportSummary(source=result.source)

    hosts = {h.ip: h for h in (await db.execute(select(Host).where(Host.scan_id == scan.id))).scalars().all()}
    ports: dict[tuple[str, int, str], Port] = {}
    if hosts:
        for port in (await db.execute(select(Port).where(Port.host_id.in_([h.id for h in hosts.values()])))).scalars():
            ports[(port.host_id, port.number, port.protocol)] = port

    def host_for(address: str | None) -> Host | None:
        if not address:
            return None
        key = _host_key(address)
        host = hosts.get(key)
        if host is None:
            imported = result.hosts.get(address)
            host = Host(
                id=new_uuid(), scan_id=scan.id, ip=key, status="up",
                hostname=(imported.hostname if imported else None) or (None if key == address else address[:255]),
                os_name=imported.os_name if imported else None,
            )
            db.add(host)
            hosts[key] = host
            summary.hosts_added += 1
        return host

    for address, imported in result.hosts.items():
        host = host_for(address)
        if host is None:
            continue
        host.hostname = host.hostname or imported.hostname
        host.os_name = host.os_name or imported.os_name
        for (number, protocol), port_info in imported.ports.items():
            if not number or (host.id, number, protocol) in ports:
                continue
            port = Port(id=new_uuid(), host_id=host.id, number=number, protocol=protocol[:5], state="open",
                        reason=f"imported from {result.source}")
            db.add(port)
            if port_info.service or port_info.product or port_info.version:
                db.add(Service(id=new_uuid(), port_id=port.id, name=(port_info.service or "")[:100] or None,
                               product=(port_info.product or "")[:255] or None,
                               version=(port_info.version or "")[:100] or None))
            ports[(host.id, number, protocol)] = port
            summary.ports_added += 1
    await db.flush()

    existing: set[tuple[str | None, str, str, int | None]] = set(
        (row[0], row[1], row[2], row[3]) for row in (await db.execute(
            select(Finding.host_id, Finding.plugin_id, Finding.title, Finding.port_number)
            .where(Finding.scan_id == scan.id)
        )).all()
    )
    new_rows: list[tuple[Finding, str | None, str]] = []
    for item in result.findings:
        host = host_for(item.address)
        key = (host.id if host else None, item.plugin_id[:100], item.title[:512], item.port)
        if key in existing:
            summary.duplicates_skipped += 1
            continue
        existing.add(key)
        finding = Finding(
            id=new_uuid(), scan_id=scan.id, host_id=host.id if host else None,
            plugin_id=item.plugin_id[:100], severity=item.severity, title=item.title[:512],
            description=item.description, remediation=item.remediation, evidence=item.evidence,
            references=json.dumps(item.references) if item.references else None,
            cvss_score=item.cvss_score, cvss_vector=(item.cvss_vector or "")[:255] or None,
            cve_ids=json.dumps(item.cve_ids) if item.cve_ids else None,
            port_number=item.port, protocol=(item.protocol or "")[:5] or None,
            first_seen_scan_id=scan.id, last_seen_scan_id=scan.id,
        )
        db.add(finding)
        new_rows.append((finding, host.ip if host else None, user_id))
        summary.findings_added += 1

    if new_rows:
        from scanr.core.priority_service import score_rows

        await score_rows(db, new_rows)
    await db.flush()

    # Recount rather than increment, so counters stay right across re-imports.
    counts: dict[str, int] = {
        severity: count for severity, count in (await db.execute(
            select(Finding.severity, func.count()).where(Finding.scan_id == scan.id).group_by(Finding.severity)
        )).all()
    }
    for severity in _SEVERITY_COLUMNS:
        setattr(scan, f"findings_{severity}", counts.get(severity, 0))
    host_count = (await db.execute(select(func.count()).select_from(Host).where(Host.scan_id == scan.id))).scalar_one()
    scan.hosts_total = max(scan.hosts_total or 0, host_count)
    scan.hosts_up = max(scan.hosts_up or 0, host_count)
    return summary
