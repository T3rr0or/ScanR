"""Attack-path graph for a scan.

Turns the scan's hosts and findings into a directed graph of attacker steps and
ranks the routes through it, so triage can start from "what chain reaches
something that matters" rather than a list sorted by CVSS.

The graph logic itself is a pure function in scanr.core.attack_path; this module
only loads the rows and serialises the result.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanr.core.attack_path import FindingInput, HostInput, build_graph
from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Finding, Host, Scan
from scanr.models.user import User

router = APIRouter(prefix="/scans/{scan_id}/attack-paths", tags=["attack-paths"])


@router.get("")
async def get_attack_paths(
    scan_id: str,
    include_inferred: bool = Query(
        True,
        description=(
            "Include clearly-marked credential-reuse hypotheses. Off gives a "
            "strictly evidence-only graph where every edge cites a finding."
        ),
    ),
    max_paths: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("findings:read")),
):
    owned = await db.execute(
        select(Scan.id).where(Scan.id == scan_id, Scan.user_id == current_user.id)
    )
    if owned.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    host_rows = (
        await db.execute(
            select(Host).where(Host.scan_id == scan_id).options(selectinload(Host.ports))
        )
    ).scalars().all()
    hosts = [
        HostInput(
            id=h.id,
            ip=h.ip,
            hostname=h.hostname,
            os_name=h.os_name,
            open_ports=tuple(p.number for p in h.ports if p.state == "open"),
        )
        for h in host_rows
    ]

    # False positives are excluded: a path built on a finding the tester has
    # already dismissed is worse than no path, and triage state is the whole
    # point of having reviewed them.
    finding_rows = (
        await db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.false_positive == False,  # noqa: E712 - SQLAlchemy idiom
            )
        )
    ).scalars().all()
    findings = [
        FindingInput(
            id=f.id,
            plugin_id=f.plugin_id,
            severity=f.severity,
            title=f.title,
            host_id=f.host_id,
            port_number=f.port_number,
            evidence=f.evidence,
        )
        for f in finding_rows
    ]

    graph = build_graph(
        hosts, findings, max_paths=max_paths, infer_credential_reuse=include_inferred
    )

    return {
        "scan_id": scan_id,
        "nodes": [
            {
                "id": n.id,
                "kind": n.kind.value,
                "label": n.label,
                "severity": n.severity,
                "meta": n.meta,
            }
            for n in graph.nodes
        ],
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "kind": e.kind.value,
                "label": e.label,
                "severity": e.severity,
                "finding_ids": e.finding_ids,
                "inferred": e.inferred,
                "cost": e.cost,
            }
            for e in graph.edges
        ],
        "paths": [
            {
                "nodes": p.nodes,
                "objective": p.objective,
                "severity": p.severity,
                "cost": p.cost,
                "length": p.length,
                "inferred": p.inferred,
                "steps": [
                    {
                        "kind": e.kind.value,
                        "label": e.label,
                        "severity": e.severity,
                        "source": e.source,
                        "target": e.target,
                        "finding_ids": e.finding_ids,
                        "inferred": e.inferred,
                    }
                    for e in p.edges
                ],
            }
            for p in graph.paths
        ],
        "chokepoints": graph.chokepoints,
        "summary": {
            "host_count": len(hosts),
            "path_count": len(graph.paths),
            "confirmed_path_count": sum(1 for p in graph.paths if not p.inferred),
            "worst_severity": graph.paths[0].severity if graph.paths else None,
        },
    }
