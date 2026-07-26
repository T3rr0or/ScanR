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

#: Ceilings on what the response may carry. Neither was capped before, so a large
#: scan handed a D3 force layout 413MB of JSON — a graph nobody can read and a
#: browser tab that will not survive it.
MAX_RESPONSE_NODES = 1500
MAX_RESPONSE_EDGES = 4000


def _cap(graph, max_nodes: int, max_edges: int):
    """Trim the graph for transport, keeping the part that answers the question.

    Everything on a ranked path is kept unconditionally — those are the routes
    the page exists to show. The remaining nodes and edges fill the budget
    worst-severity-and-cheapest first, so what survives is what an attacker would
    reach for. Returns (nodes, edges, truncated).
    """
    from scanr.core.attack_path import _SEVERITY_RANK  # noqa: PLC0415

    if len(graph.nodes) <= max_nodes and len(graph.edges) <= max_edges:
        return graph.nodes, graph.edges, False

    keep_nodes: set[str] = {n for p in graph.paths for n in p.nodes}
    keep_edges = {(e.source, e.target, e.kind) for p in graph.paths for e in p.edges}

    def edge_rank(e):
        return (-_SEVERITY_RANK.get(e.severity, 0), e.inferred, e.cost)

    for e in sorted(graph.edges, key=edge_rank):
        if len(keep_edges) >= max_edges or len(keep_nodes) >= max_nodes:
            break
        keep_edges.add((e.source, e.target, e.kind))
        keep_nodes.update((e.source, e.target))

    nodes = [n for n in graph.nodes if n.id in keep_nodes]
    # Only edges whose endpoints both survived — a dangling edge breaks the layout.
    edges = [
        e for e in graph.edges
        if (e.source, e.target, e.kind) in keep_edges
        and e.source in keep_nodes and e.target in keep_nodes
    ]
    return nodes, edges, True


@router.get("")
async def get_attack_paths(
    scan_id: str,
    include_inferred: bool = Query(
        False,
        description=(
            "Include clearly-marked credential-reuse hypotheses. Off (the default) "
            "gives a strictly evidence-only graph where every edge cites a finding. "
            "On, the inference is credentials × hosts and dominates the graph — 92% "
            "of edges on a 1000-host scan — while never appearing in a ranked path, "
            "so turn it on only for a sparse scan where nothing else connects."
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

    # The response goes straight into a D3 force layout, which is unusable long
    # before it is large: an uncapped 4000-host graph produced 413MB of JSON.
    # Ranked paths and their nodes are always kept — they are the answer; the
    # surrounding cloud is context, and context is what gets dropped.
    nodes, edges, truncated = _cap(graph, MAX_RESPONSE_NODES, MAX_RESPONSE_EDGES)

    # "No attack paths" is ambiguous now that inference is off by default: it can
    # mean "nothing connects" or "the only route was a hypothesis". A scan whose
    # sole route is inference-only reads as a regression to anyone who does not
    # know the default flipped, so say which case this is — with a real count,
    # not a hint. The extra build only happens when there was nothing to report,
    # so a normal request never pays for it.
    inferred_available: int | None = None
    if not include_inferred and not graph.paths:
        hypothetical = build_graph(
            hosts, findings, max_paths=max_paths, infer_credential_reuse=True
        )
        inferred_available = len(hypothetical.paths)

    return {
        "scan_id": scan_id,
        "truncated": truncated,
        #: Non-null only when the evidence-only graph found nothing: how many
        #: routes appear if credential-reuse hypotheses are included. 0 means
        #: nothing connects at all.
        "inferred_paths_available": inferred_available,
        "totals": {"nodes": len(graph.nodes), "edges": len(graph.edges)},
        "nodes": [
            {
                "id": n.id,
                "kind": n.kind.value,
                "label": n.label,
                "severity": n.severity,
                "meta": n.meta,
            }
            for n in nodes
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
            for e in edges
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
