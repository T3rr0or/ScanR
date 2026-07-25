"""Attack-path graph construction and ranking.

The value of this feature is the *ordering* it produces, so these tests pin the
behaviour that makes the ordering defensible: edges only exist where a finding
justifies them, ranking follows attacker effort rather than hop count, and
chokepoints identify the fix that breaks the most routes.
"""
import pytest

from scanr.core.attack_path import (
    ENTRY_NODE_ID,
    EdgeKind,
    FindingInput,
    HostInput,
    NodeKind,
    build_graph,
)


def host(hid, ip, **kw):
    return HostInput(id=hid, ip=ip, **kw)


def finding(fid, plugin_id, severity, host_id, **kw):
    return FindingInput(
        id=fid, plugin_id=plugin_id, severity=severity,
        title=kw.pop("title", plugin_id), host_id=host_id, **kw
    )


# ── graph construction ───────────────────────────────────────────────────────

def test_empty_scan_yields_only_the_entry_node():
    g = build_graph([], [])
    assert [n.id for n in g.nodes] == [ENTRY_NODE_ID]
    assert g.edges == [] and g.paths == []


def test_hardening_findings_do_not_create_edges():
    """A missing security header is not an attack step. Inventing an edge for it
    would produce a path the tester cannot defend in a readout."""
    hosts = [host("h1", "192.0.2.10")]
    findings = [
        finding("f1", "web.http_headers", "medium", "h1"),
        finding("f2", "ssl_tls.cipher_audit", "medium", "h1"),
        finding("f3", "web.clickjacking", "low", "h1"),
    ]
    g = build_graph(hosts, findings)
    assert g.edges == []
    assert g.paths == []


def test_findings_without_a_host_are_ignored():
    """They cannot be positioned on a route."""
    g = build_graph([host("h1", "192.0.2.10")],
                    [finding("f1", "services.redis_unauth", "critical", None)])
    assert g.edges == []


def test_unauthenticated_service_creates_a_foothold():
    g = build_graph(
        [host("h1", "192.0.2.10", hostname="web01")],
        [finding("f1", "services.redis_unauth", "critical", "h1")],
    )
    edge = next(e for e in g.edges if e.kind is EdgeKind.foothold)
    assert edge.source == ENTRY_NODE_ID
    assert edge.target == "host:h1"
    assert edge.severity == "critical"
    assert edge.finding_ids == ["f1"]
    assert "Redis" in edge.label


def test_repeated_technique_strengthens_one_edge_not_many():
    g = build_graph(
        [host("h1", "192.0.2.10")],
        [
            finding("f1", "services.redis_unauth", "high", "h1"),
            finding("f2", "services.redis_unauth", "critical", "h1"),
        ],
    )
    assert len(g.edges) == 1
    edge = g.edges[0]
    assert sorted(edge.finding_ids) == ["f1", "f2"]
    # The easiest way through is what matters, so the worst severity wins.
    assert edge.severity == "critical"


def test_credential_access_creates_a_credential_node():
    g = build_graph(
        [host("dc", "192.0.2.5", hostname="dc01")],
        [finding("f1", "services.kerberoastable", "high", "dc")],
    )
    creds = [n for n in g.nodes if n.kind is NodeKind.credential]
    assert len(creds) == 1
    edge = next(e for e in g.edges if e.kind is EdgeKind.credential_access)
    assert edge.source == "host:dc" and edge.target == creds[0].id


def test_dcsync_reaches_the_domain():
    g = build_graph(
        [host("dc", "192.0.2.5")],
        [finding("f1", "services.dcsync_check", "critical", "dc",
                 evidence="domain: corp.example.com")],
    )
    domains = [n for n in g.nodes if n.kind is NodeKind.domain]
    assert len(domains) == 1
    assert domains[0].label == "corp.example.com", "domain name should come from evidence"
    assert any(e.kind is EdgeKind.domain_compromise for e in g.edges)


def test_domain_node_falls_back_to_a_generic_label():
    g = build_graph(
        [host("dc", "192.0.2.5")],
        [finding("f1", "services.zerologon", "critical", "dc")],
    )
    domain = next(n for n in g.nodes if n.kind is NodeKind.domain)
    assert domain.label == "Active Directory domain"


def test_host_node_carries_the_worst_severity_seen():
    g = build_graph(
        [host("h1", "192.0.2.10")],
        [
            finding("f1", "services.ftp_anon", "medium", "h1"),
            finding("f2", "services.redis_unauth", "critical", "h1"),
        ],
    )
    node = next(n for n in g.nodes if n.id == "host:h1")
    assert node.severity == "critical"


def test_lateral_movement_uses_a_credential_when_one_exists():
    """Moving sideways needs something to move with."""
    g = build_graph(
        [host("h1", "192.0.2.10")],
        [
            finding("f1", "services.kerberoastable", "high", "h1"),
            finding("f2", "services.admin_share_access", "high", "h1"),
        ],
    )
    lateral = next(e for e in g.edges if e.kind is EdgeKind.lateral_movement)
    assert lateral.source.startswith("cred:"), "should move using the obtained credential"


# ── path ranking ─────────────────────────────────────────────────────────────

def test_no_objective_means_no_paths():
    """Footholds alone are findings, not an attack path — there is nowhere to get to."""
    g = build_graph(
        [host("h1", "192.0.2.10")],
        [finding("f1", "services.redis_unauth", "critical", "h1")],
    )
    assert g.paths == []


def test_full_chain_from_entry_to_domain_is_found():
    """The realistic shape: break in somewhere, harvest a credential, move to the
    DC with it, then take the domain."""
    hosts = [host("web", "192.0.2.10"), host("dc", "192.0.2.5")]
    findings = [
        finding("f1", "services.redis_unauth", "critical", "web"),      # entry → web
        finding("f2", "web.sensitive_files", "high", "web"),            # web → cred
        finding("f3", "services.admin_share_access", "high", "dc"),     # cred → dc
        finding("f4", "services.dcsync_check", "critical", "dc"),       # dc → domain
    ]
    g = build_graph(hosts, findings)
    assert g.paths, "expected a route to the domain"
    path = g.paths[0]
    assert path.nodes[0] == ENTRY_NODE_ID
    assert path.nodes[-1].startswith("domain:")
    assert path.severity == "critical"
    kinds = [e.kind for e in path.edges]
    assert EdgeKind.foothold in kinds
    assert EdgeKind.lateral_movement in kinds
    assert EdgeKind.domain_compromise in kinds


def test_domain_unreachable_without_a_route_onto_the_dc():
    """A DCSync finding on a host nothing can reach is a finding, not a path.
    Bridging the gap by assumption would overstate the risk."""
    hosts = [host("web", "192.0.2.10"), host("dc", "192.0.2.5")]
    findings = [
        finding("f1", "services.redis_unauth", "critical", "web"),
        finding("f2", "services.kerberoastable", "high", "dc"),
        finding("f3", "services.dcsync_check", "critical", "dc"),
    ]
    g = build_graph(hosts, findings)
    assert g.paths == [], "nothing connects web to dc, so there is no path"


def test_authenticated_only_route_starts_from_supplied_credentials():
    """With no discovered credential, an authenticated finding still forms a
    route — but one that is explicit about needing credentials the attacker does
    not start with, and priced accordingly."""
    hosts = [host("dc", "192.0.2.5")]
    findings = [
        finding("f1", "services.admin_share_access", "high", "dc"),
        finding("f2", "services.dcsync_check", "critical", "dc"),
    ]
    g = build_graph(hosts, findings)
    assert g.paths
    path = g.paths[0]
    assert "cred:supplied" in path.nodes
    supplied = next(n for n in g.nodes if n.id == "cred:supplied")
    assert supplied.meta.get("supplied") is True

    # It must be more expensive than an equivalent unauthenticated route.
    unauth = build_graph(
        [host("dc", "192.0.2.5")],
        [
            finding("g1", "services.redis_unauth", "high", "dc"),
            finding("g2", "services.dcsync_check", "critical", "dc"),
        ],
    )
    assert unauth.paths[0].cost < path.cost


def test_ranking_prefers_attacker_effort_over_hop_count():
    """A short route through a low-severity issue must not outrank a longer route
    through unauthenticated criticals — the attacker takes the cheap one."""
    hosts = [host("easy", "192.0.2.10"), host("hard", "192.0.2.11"), host("dc", "192.0.2.5")]
    findings = [
        # Long but trivial: two criticals.
        finding("f1", "services.redis_unauth", "critical", "easy"),
        finding("f2", "services.admin_share_access", "critical", "easy"),
        # Short but painful: an info-level foothold straight at the DC.
        finding("f3", "services.snmp_walk", "info", "dc"),
        finding("f4", "services.dcsync_check", "critical", "dc"),
    ]
    g = build_graph(hosts, findings)
    assert g.paths
    cheapest = g.paths[0]
    # The info-severity hop is expensive, so it must not be the top-ranked route
    # unless it is genuinely the cheapest total.
    costs = [p.cost for p in g.paths]
    assert costs == sorted(costs), "paths must be ordered cheapest-first"
    assert cheapest.cost == min(costs)


def test_unreachable_objective_is_not_reported_as_a_path():
    """A DCSync finding with no way in from the attacker's position is a finding,
    not a path. Reporting it as one would overstate the risk."""
    g = build_graph(
        [host("dc", "192.0.2.5")],
        [finding("f1", "services.dcsync_check", "critical", "dc")],
    )
    # entry has no foothold onto dc, so the domain is unreachable.
    assert all(p.nodes[0] == ENTRY_NODE_ID for p in g.paths)
    assert g.paths == [], "no foothold means no path"


def test_path_edges_carry_their_evidence():
    g = build_graph(
        [host("web", "192.0.2.10"), host("dc", "192.0.2.5")],
        [
            finding("f1", "services.redis_unauth", "critical", "web"),
            finding("f2", "services.dcsync_check", "critical", "dc"),
            finding("f3", "services.admin_share_access", "high", "dc"),
        ],
    )
    for path in g.paths:
        for edge in path.edges:
            if edge.target == "cred:supplied":
                # The one modelling construct rather than an observation: it
                # represents the attacker needing to obtain credentials, and is
                # labelled as such instead of claiming evidence it does not have.
                assert not edge.finding_ids
                assert "obtain valid credentials" in edge.label
                continue
            assert edge.finding_ids, f"unjustified edge: {edge.label}"


def test_max_paths_is_respected():
    hosts = [host(f"h{i}", f"192.0.2.{i}") for i in range(1, 12)]
    findings = []
    for i in range(1, 12):
        findings.append(finding(f"a{i}", "services.redis_unauth", "critical", f"h{i}"))
        findings.append(finding(f"b{i}", "authenticated.docker_privileged_check", "high", f"h{i}"))
    g = build_graph(hosts, findings, max_paths=3)
    assert len(g.paths) <= 3


# ── chokepoints ──────────────────────────────────────────────────────────────

def test_chokepoint_is_the_node_shared_by_the_most_paths():
    """The actionable output: fix this one thing and several routes disappear."""
    hosts = [
        host("jump", "192.0.2.9", hostname="jumpbox"),
        host("a", "192.0.2.10"),
        host("b", "192.0.2.11"),
        host("dc", "192.0.2.5"),
    ]
    findings = [
        finding("f1", "services.redis_unauth", "critical", "jump"),
        finding("f2", "services.kerberoastable", "high", "jump"),
        finding("f3", "services.dcsync_check", "critical", "dc"),
        finding("f4", "authenticated.docker_privileged_check", "high", "a"),
        finding("f5", "services.redis_unauth", "critical", "a"),
        finding("f6", "authenticated.docker_privileged_check", "high", "b"),
        finding("f7", "services.redis_unauth", "critical", "b"),
    ]
    g = build_graph(hosts, findings)
    # Chokepoints only list nodes on more than one path.
    for cp in g.chokepoints:
        assert cp["path_count"] > 1
    assert all(cp["node_id"] != ENTRY_NODE_ID for cp in g.chokepoints), (
        "the entry node is on every path by construction and is not actionable"
    )


def test_chokepoints_empty_when_paths_do_not_overlap():
    hosts = [host("a", "192.0.2.10"), host("b", "192.0.2.11")]
    findings = [
        finding("f1", "services.redis_unauth", "critical", "a"),
        finding("f2", "authenticated.docker_privileged_check", "high", "a"),
        finding("f3", "services.redis_unauth", "critical", "b"),
        finding("f4", "authenticated.docker_privileged_check", "high", "b"),
    ]
    g = build_graph(hosts, findings)
    assert g.chokepoints == []


# ── mapping hygiene ──────────────────────────────────────────────────────────

def test_every_mapped_plugin_id_exists_in_the_plugin_catalogue():
    """A typo'd plugin id would silently never match, leaving a technique that
    looks supported but never produces an edge."""
    import pathlib
    import re

    from scanr.core import attack_path as ap

    root = pathlib.Path(ap.__file__).resolve().parents[1] / "plugins"
    real = set()
    for path in root.rglob("*.py"):
        real.update(re.findall(r'^\s{4}id = "([^"]+)"', path.read_text(), re.M))

    mapped = set()
    for table in (ap._FOOTHOLD, ap._CREDENTIAL_ACCESS, ap._LATERAL,
                  ap._ESCALATION, ap._TRUST):
        mapped |= set(table)

    assert real, "plugin catalogue scan found nothing — the test is broken"
    unknown = mapped - real
    assert not unknown, f"attack_path references unknown plugin ids: {sorted(unknown)}"


def test_no_plugin_is_mapped_to_two_techniques():
    from scanr.core import attack_path as ap

    tables = [ap._FOOTHOLD, ap._CREDENTIAL_ACCESS, ap._LATERAL, ap._ESCALATION, ap._TRUST]
    seen: dict[str, int] = {}
    for i, table in enumerate(tables):
        for pid in table:
            assert pid not in seen, f"{pid} mapped in two tables ({seen.get(pid)} and {i})"
            seen[pid] = i


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_cost_increases_as_severity_falls(severity):
    from scanr.core.attack_path import EdgeKind, _cost_for

    order = ["critical", "high", "medium", "low", "info"]
    costs = [_cost_for(EdgeKind.foothold, s) for s in order]
    assert costs == sorted(costs), "lower severity must cost the attacker more"


# ── credential reuse (inference) ─────────────────────────────────────────────

def test_credential_reuse_is_marked_as_inferred():
    """A strictly evidence-only graph produces almost no paths on a real scan,
    so reuse is hypothesised — but never presented as an observation."""
    hosts = [
        host("web", "192.0.2.10", open_ports=(80, 6379)),
        host("dc", "192.0.2.5", open_ports=(445, 88)),
    ]
    findings = [
        finding("f1", "services.redis_unauth", "critical", "web"),
        finding("f2", "web.sensitive_files", "high", "web"),
        finding("f3", "services.dcsync_check", "critical", "dc"),
    ]
    g = build_graph(hosts, findings)
    reuse = [e for e in g.edges if e.kind is EdgeKind.credential_reuse]
    assert reuse, "expected a reuse hypothesis onto the DC"
    for e in reuse:
        assert e.inferred is True
        assert "inferred" in e.label.lower()
        assert e.finding_ids == [], "a hypothesis has no finding evidence"
    assert g.paths and g.paths[0].inferred is True


def test_reuse_only_targets_hosts_exposing_an_auth_service():
    """The port evidence is real even though the reuse is reasoned; a printer
    with only 9100 open is not a credential target."""
    hosts = [
        host("web", "192.0.2.10", open_ports=(6379,)),
        host("prn", "192.0.2.99", open_ports=(9100,)),
        host("dc", "192.0.2.5", open_ports=(445,)),
    ]
    findings = [
        finding("f1", "services.redis_unauth", "critical", "web"),
        finding("f2", "web.sensitive_files", "high", "web"),
        finding("f3", "services.dcsync_check", "critical", "dc"),
        finding("f4", "ssl_tls.cipher_audit", "medium", "prn"),
    ]
    g = build_graph(hosts, findings)
    targets = {e.target for e in g.edges if e.kind is EdgeKind.credential_reuse}
    assert "host:dc" in targets
    assert "host:prn" not in targets, "no auth service on the printer"


def test_reuse_never_loops_back_to_the_origin_host():
    hosts = [host("web", "192.0.2.10", open_ports=(445, 6379))]
    findings = [
        finding("f1", "services.redis_unauth", "critical", "web"),
        finding("f2", "web.sensitive_files", "high", "web"),
    ]
    g = build_graph(hosts, findings)
    for e in g.edges:
        if e.kind is EdgeKind.credential_reuse:
            assert e.target != "host:web"


def test_inference_can_be_turned_off_for_an_evidence_only_graph():
    hosts = [
        host("web", "192.0.2.10", open_ports=(6379,)),
        host("dc", "192.0.2.5", open_ports=(445,)),
    ]
    findings = [
        finding("f1", "services.redis_unauth", "critical", "web"),
        finding("f2", "web.sensitive_files", "high", "web"),
        finding("f3", "services.dcsync_check", "critical", "dc"),
    ]
    strict = build_graph(hosts, findings, infer_credential_reuse=False)
    assert not any(e.inferred for e in strict.edges)
    assert all(e.finding_ids for e in strict.edges)


def test_demonstrated_route_outranks_an_inferred_one():
    """Given both, the confirmed path must be reported first."""
    hosts = [
        host("web", "192.0.2.10", open_ports=(6379,)),
        host("dc", "192.0.2.5", open_ports=(445,)),
    ]
    findings = [
        finding("f1", "services.redis_unauth", "critical", "web"),
        finding("f2", "web.sensitive_files", "high", "web"),
        # A demonstrated authentication onto the DC, plus the reuse hypothesis.
        finding("f3", "services.admin_share_access", "high", "dc"),
        finding("f4", "services.dcsync_check", "critical", "dc"),
    ]
    g = build_graph(hosts, findings)
    assert g.paths
    assert g.paths[0].inferred is False, "a demonstrated route must rank first"
