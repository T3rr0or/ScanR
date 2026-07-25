"""Attack-path graph: how an attacker gets from outside to something that matters.

ScanR already collects the pieces — hosts, findings, credentials, AD trust and
delegation data — but presents them as a flat list where a critical finding on a
jump box and a critical finding on an isolated printer look identical. This turns
those pieces into a directed graph and ranks the routes through it, so the answer
to "what should we fix first" is "the step that breaks the most paths" rather than
"the finding with the biggest CVSS".

Design constraints, in priority order:

1. **Evidence-only.** Every edge is backed by at least one real finding from this
   scan. Nothing is inferred from "this port is usually exploitable". A path the
   tester cannot point at evidence for is worse than no path at all, because it
   costs their credibility with the client.
2. **Attacker-preference costs.** Path search minimises attacker effort, not hop
   count: a two-hop route through an unauthenticated RCE outranks a one-hop route
   through a theoretical info leak.
3. **Pure and synchronous.** Takes plain dataclasses, returns plain dataclasses.
   No DB, no I/O — so the ranking logic is testable without a scan.
"""
from __future__ import annotations

import heapq
import re
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "AttackGraph",
    "AttackPath",
    "Edge",
    "EdgeKind",
    "FindingInput",
    "HostInput",
    "Node",
    "NodeKind",
    "build_graph",
]


class NodeKind(str, Enum):
    entry = "entry"            # the tester's vantage point — every path starts here
    host = "host"
    credential = "credential"  # an identity or secret the attacker obtains
    domain = "domain"          # AD domain: reaching it is game over


class EdgeKind(str, Enum):
    foothold = "foothold"                    # entry → host: get onto something
    credential_access = "credential_access"  # host → credential: obtain a secret
    lateral_movement = "lateral_movement"    # credential/host → host: move sideways
    credential_reuse = "credential_reuse"    # inferred: try a credential elsewhere
    privilege_escalation = "privilege_escalation"  # gain rights where you already are
    domain_compromise = "domain_compromise"  # → domain: full control


#: Ports whose presence means a host will accept a credential. Used to decide
#: where credential reuse is worth *hypothesising* — see _add_reuse_edges.
_AUTH_PORTS: dict[int, str] = {
    22: "SSH",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM (TLS)",
    389: "LDAP",
    636: "LDAPS",
    88: "Kerberos",
    1433: "MSSQL",
    5432: "PostgreSQL",
    3306: "MySQL",
}


#: Objectives a path is trying to reach. Reaching one of these is what makes a
#: route worth reporting rather than just a list of hops.
_OBJECTIVE_EDGES = frozenset({EdgeKind.domain_compromise, EdgeKind.privilege_escalation})


@dataclass(frozen=True)
class HostInput:
    """The subset of a Host row the graph needs."""
    id: str
    ip: str
    hostname: str | None = None
    os_name: str | None = None
    open_ports: tuple[int, ...] = ()


@dataclass(frozen=True)
class FindingInput:
    """The subset of a Finding row the graph needs."""
    id: str
    plugin_id: str
    severity: str
    title: str
    host_id: str | None = None
    port_number: int | None = None
    evidence: str | None = None


@dataclass
class Node:
    id: str
    kind: NodeKind
    label: str
    #: worst finding severity attached to this node, for display
    severity: str = "info"
    meta: dict = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    kind: EdgeKind
    label: str
    severity: str
    #: finding ids justifying this edge — the tester's evidence trail
    finding_ids: list[str] = field(default_factory=list)
    #: attacker effort, lower is easier. Derived from severity + technique.
    cost: float = 1.0
    #: True when the step is a reasoned hypothesis rather than something the scan
    #: demonstrated. Surfaced so a report never presents inference as observation.
    inferred: bool = False


@dataclass
class AttackPath:
    """One route from the entry point to an objective."""
    nodes: list[str]
    edges: list[Edge]
    #: total attacker effort; lower means easier for the attacker, so worse for us
    cost: float
    #: worst severity along the route
    severity: str
    objective: str

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def inferred(self) -> bool:
        """True if any step is a hypothesis rather than a demonstrated result.

        A path with this set still belongs in a report, but as "likely reachable"
        rather than "confirmed reachable".
        """
        return any(e.inferred for e in self.edges)


@dataclass
class AttackGraph:
    nodes: list[Node]
    edges: list[Edge]
    paths: list[AttackPath]
    #: nodes that appear in the most distinct paths — the highest-leverage fixes
    chokepoints: list[dict] = field(default_factory=list)


# ── severity → attacker effort ───────────────────────────────────────────────
# Lower cost = easier for the attacker. A critical unauthenticated RCE is close to
# free; an informational leak is expensive to turn into access. Path search
# therefore prefers the route a real attacker would actually take, which is not
# necessarily the shortest one.
_SEVERITY_COST = {
    "critical": 1.0,
    "high": 2.0,
    "medium": 4.0,
    "low": 8.0,
    "info": 16.0,
}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _worst(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


# ── plugin → attack technique mapping ────────────────────────────────────────
# Only plugins that represent a real attacker *step* appear here. A finding that
# is a hardening observation (missing header, weak cipher) is deliberately absent:
# including it would produce paths a tester cannot defend in a readout.

#: entry → host. Unauthenticated access, code execution, or a service that hands
#: over data without asking who you are.
_FOOTHOLD: dict[str, str] = {
    # Remote code execution
    "services.ms17_010_check": "EternalBlue RCE (MS17-010)",
    "services.bluekeep_check": "BlueKeep RCE (CVE-2019-0708)",
    "services.printnightmare": "PrintNightmare RCE",
    "web.log4shell_check": "Log4Shell RCE",
    "web.spring4shell_check": "Spring4Shell RCE",
    "web.deserial_probe": "Insecure deserialization RCE",
    "services.java_rmi_jmx": "Exposed Java RMI/JMX",
    "web.ssti_detect": "Server-side template injection",
    "web.sqli_detect": "SQL injection",
    "web.sqli_blind": "Blind SQL injection",
    "web.path_traversal": "Path traversal",
    "web.xxe_detect": "XXE",
    "services.adb_unauth": "Exposed Android Debug Bridge",
    # Unauthenticated services
    "services.docker_daemon_unauth": "Unauthenticated Docker daemon",
    "services.kubernetes_api_unauth": "Unauthenticated Kubernetes API",
    "services.etcd_unauth": "Unauthenticated etcd",
    "services.redis_unauth": "Unauthenticated Redis",
    "services.mongodb_unauth": "Unauthenticated MongoDB",
    "services.elasticsearch_unauth": "Unauthenticated Elasticsearch",
    "services.mysql_unauth": "Unauthenticated MySQL",
    "services.postgres_unauth": "Unauthenticated PostgreSQL",
    "services.mssql_unauth": "Unauthenticated MSSQL",
    "services.couchdb_unauth": "Unauthenticated CouchDB",
    "services.cassandra_unauth": "Unauthenticated Cassandra",
    "services.clickhouse_unauth": "Unauthenticated ClickHouse",
    "services.influxdb_unauth": "Unauthenticated InfluxDB",
    "services.memcached_unauth": "Unauthenticated Memcached",
    "services.neo4j_unauth": "Unauthenticated Neo4j",
    "services.jupyter_unauth": "Unauthenticated Jupyter",
    "services.docker_registry_exposure": "Exposed Docker registry",
    "services.jenkins_exposure": "Exposed Jenkins",
    "services.gitlab_exposure": "Exposed GitLab",
    "services.grafana_exposure": "Exposed Grafana",
    "services.prometheus_exposure": "Exposed Prometheus",
    "services.minio_s3_exposure": "Exposed MinIO/S3",
    "services.solr_admin_exposure": "Exposed Solr admin",
    "services.consul_vault_nomad_exposure": "Exposed Consul/Vault/Nomad",
    "services.rabbitmq_kafka_zookeeper_exposure": "Exposed message broker",
    "services.cisco_smart_install": "Cisco Smart Install exposure",
    "services.ipmi_cipher_zero": "IPMI cipher-zero authentication bypass",
    # Default / weak / anonymous authentication
    "ssh.ssh_default_creds": "Default SSH credentials",
    "web.default_creds_web": "Default web credentials",
    "services.firebird_default_creds": "Default Firebird credentials",
    "services.vnc_auth": "VNC without authentication",
    "services.telnet_detect": "Telnet (cleartext, often default creds)",
    "services.ftp_anon": "Anonymous FTP",
    "services.smb_null_session": "SMB null session",
    "services.smb_guest_access": "SMB guest access",
    "services.ldap_anon_bind": "Anonymous LDAP bind",
    "services.nfs_shares": "Exported NFS share",
    "services.snmp_walk": "SNMP read access",
}

#: host → credential. The finding yields a secret, hash, or identity.
_CREDENTIAL_ACCESS: dict[str, str] = {
    "services.kerberoastable": "Kerberoastable service account",
    "services.asreproastable": "AS-REP roastable account",
    "services.gmsa_readable": "Readable gMSA password blob",
    "services.snmp_community": "Guessable SNMP community string",
    "services.ldap_user_enum": "LDAP user enumeration",
    "services.netbios_info": "NetBIOS account disclosure",
    "web.api_key_exposure": "Exposed API key",
    "web.sensitive_files": "Exposed sensitive file",
    "services.ike_aggressive_mode": "IKE aggressive mode PSK hash",
    "services.ftp_cleartext": "Cleartext FTP credentials",
    "services.ntlmrelay_opportunity": "NTLM relay opportunity",
    "services.smb_signing": "SMB signing disabled (relay/coerce)",
    "services.ldap_signing": "LDAP signing not enforced (relay)",
    "services.ldap_channel_binding": "LDAP channel binding not enforced (relay)",
    "services.llmnr_nbns_check": "LLMNR/NBT-NS poisoning",
    "services.llmnr_mdns_ssdp_exposure": "LLMNR/mDNS/SSDP poisoning",
    "web.jwt_misconfig": "Forgeable JWT",
    "web.jwt_extended": "Forgeable JWT",
}

#: credential/host → host. Using access you already have to reach another host.
_LATERAL: dict[str, str] = {
    "services.admin_share_access": "Administrative share access",
    "services.smb_authenticated_enum": "Authenticated SMB access",
    "services.winrm_access": "WinRM remote execution",
    "services.winrm_basic_auth": "WinRM basic authentication",
    "services.smb_share_enum": "Readable SMB share",
    "services.k8s_rbac_enum": "Over-permissive Kubernetes RBAC",
}

#: → domain / elevated rights. Reaching one of these ends the engagement.
_ESCALATION: dict[str, str] = {
    "services.dcsync_check": "DCSync — replicate directory secrets",
    "services.zerologon": "Zerologon — domain controller takeover",
    "services.unconstrained_delegation": "Unconstrained delegation abuse",
    "services.adcs_enum": "AD CS certificate abuse",
    "services.ad_password_policy": "Weak domain password policy",
    "authenticated.docker_privileged_check": "Privileged container escape",
}

#: host → domain, as a relationship rather than a compromise.
_TRUST = {"services.trust_enum": "Domain trust relationship"}

ENTRY_NODE_ID = "entry"


def _cost_for(kind: EdgeKind, severity: str) -> float:
    """Attacker effort for one step.

    Severity carries most of it, then a per-technique multiplier: obtaining a
    credential and then reusing it is more work than walking through an
    unauthenticated RCE, even when both findings are marked critical.
    """
    base = _SEVERITY_COST.get(severity, 16.0)
    multiplier = {
        EdgeKind.foothold: 1.0,
        EdgeKind.credential_access: 1.5,
        EdgeKind.lateral_movement: 1.25,
        # Inferred, so deliberately expensive: any route that needs it should rank
        # below one the scan actually demonstrated.
        EdgeKind.credential_reuse: 3.0,
        EdgeKind.privilege_escalation: 1.0,
        EdgeKind.domain_compromise: 0.75,  # the attacker's goal — they will pay for it
    }[kind]
    return base * multiplier


_DOMAIN_RE = re.compile(r"\b(?:domain|realm|dnsdomain)\s*[:=]\s*([A-Za-z0-9._-]+)", re.I)


def _domain_from(findings: list[FindingInput]) -> str | None:
    """Best-effort AD domain name from finding evidence, for the domain node label."""
    for f in findings:
        if not f.evidence:
            continue
        match = _DOMAIN_RE.search(f.evidence)
        if match:
            name = match.group(1).strip(".").lower()
            if name and "." in name:
                return name
    return None


def _add_reuse_edges(
    nodes: dict[str, Node],
    edges: dict[tuple[str, str, EdgeKind], Edge],
    hosts: list[HostInput],
) -> None:
    """Draw credential-reuse hypotheses from each obtained credential.

    Only to hosts that expose an authentication service the scan actually saw, and
    never back to the host the credential came from. Marked inferred so a reader
    can tell a hypothesis from an observation.
    """
    creds = [n for n in nodes.values() if n.kind is NodeKind.credential]
    if not creds:
        return
    for cred in creds:
        origin = cred.meta.get("from_host")
        for host in hosts:
            if host.ip == origin:
                continue
            open_auth = [p for p in host.open_ports if p in _AUTH_PORTS]
            if not open_auth:
                continue
            target = f"host:{host.id}"
            if target not in nodes:
                continue  # host has no findings, so it is not in the graph
            key = (cred.id, target, EdgeKind.credential_reuse)
            if key in edges:
                continue
            services = ", ".join(sorted({_AUTH_PORTS[p] for p in open_auth}))
            edges[key] = Edge(
                source=cred.id,
                target=target,
                kind=EdgeKind.credential_reuse,
                label=f"Credential reuse against {services} (inferred)",
                severity=cred.severity,
                finding_ids=[],
                cost=_cost_for(EdgeKind.credential_reuse, cred.severity),
                inferred=True,
            )


def build_graph(
    hosts: list[HostInput],
    findings: list[FindingInput],
    *,
    max_paths: int = 25,
    infer_credential_reuse: bool = True,
) -> AttackGraph:
    """Build the attack graph and rank the routes through it.

    ``infer_credential_reuse`` adds clearly-marked hypothesis edges where a
    credential could plausibly be replayed. Turn it off for a strictly
    evidence-only graph (every edge backed by a finding).
    """
    by_host = {h.id: h for h in hosts}
    nodes: dict[str, Node] = {
        ENTRY_NODE_ID: Node(
            id=ENTRY_NODE_ID, kind=NodeKind.entry, label="Attacker position",
        )
    }
    # (source, target, kind) -> Edge, so repeated findings of the same technique
    # against the same pair strengthen one edge instead of cluttering the graph.
    edges: dict[tuple[str, str, EdgeKind], Edge] = {}

    def host_node(host: HostInput) -> str:
        nid = f"host:{host.id}"
        if nid not in nodes:
            label = host.hostname or host.ip
            nodes[nid] = Node(
                id=nid, kind=NodeKind.host, label=label,
                meta={
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "os_name": host.os_name,
                    "open_ports": list(host.open_ports),
                },
            )
        return nid

    def cred_node(host: HostInput, technique: str) -> str:
        # One credential node per (host, technique): two different roastable
        # accounts on one DC are the same attacker step, but a roastable account
        # and a leaked API key are not.
        nid = f"cred:{host.id}:{technique}"
        if nid not in nodes:
            nodes[nid] = Node(
                id=nid, kind=NodeKind.credential, label=technique,
                meta={"from_host": host.ip},
            )
        return nid

    domain_name = _domain_from(findings)
    domain_id: str | None = None
    supplied_cred_id: str | None = None
    # Lateral findings are resolved in a second pass: they need to know which
    # credentials the scan discovered anywhere, which is only known once every
    # finding has been walked.
    lateral_findings: list[tuple[FindingInput, HostInput, str]] = []

    def supplied_cred_node() -> str:
        """Stand-in for credentials the operator gave the scanner.

        An authenticated finding proves a credential works, but not that an
        attacker could obtain one. Modelling that as a node with an expensive
        inbound edge keeps such routes visible — they are real findings for a
        credentialed assessment — while ranking them below anything reachable
        without credentials.
        """
        nonlocal supplied_cred_id
        if supplied_cred_id is None:
            supplied_cred_id = "cred:supplied"
            nodes[supplied_cred_id] = Node(
                id=supplied_cred_id, kind=NodeKind.credential,
                label="Operator-supplied credentials",
                meta={"supplied": True},
            )
            edges[(ENTRY_NODE_ID, supplied_cred_id, EdgeKind.credential_access)] = Edge(
                source=ENTRY_NODE_ID, target=supplied_cred_id,
                kind=EdgeKind.credential_access,
                label="Attacker must first obtain valid credentials",
                severity="info",
                finding_ids=[],
                # Deliberately expensive: an attacker does not start with these.
                cost=_SEVERITY_COST["info"] * 2,
            )
        return supplied_cred_id

    def domain_node() -> str:
        nonlocal domain_id
        if domain_id is None:
            domain_id = f"domain:{domain_name or 'active-directory'}"
            nodes[domain_id] = Node(
                id=domain_id, kind=NodeKind.domain,
                label=domain_name or "Active Directory domain",
                severity="critical",
            )
        return domain_id

    def add_edge(src: str, dst: str, kind: EdgeKind, label: str, f: FindingInput) -> None:
        key = (src, dst, kind)
        existing = edges.get(key)
        if existing is None:
            edges[key] = Edge(
                source=src, target=dst, kind=kind, label=label,
                severity=f.severity, finding_ids=[f.id],
                cost=_cost_for(kind, f.severity),
            )
            return
        existing.finding_ids.append(f.id)
        # Keep the worst severity — the easiest way through is what matters.
        if _SEVERITY_RANK.get(f.severity, 0) > _SEVERITY_RANK.get(existing.severity, 0):
            existing.severity = f.severity
            existing.label = label
            existing.cost = _cost_for(kind, f.severity)

    for f in findings:
        host = by_host.get(f.host_id) if f.host_id else None
        if host is None:
            # A finding with no host cannot be positioned on a route.
            continue
        h_node = host_node(host)
        node = nodes[h_node]
        node.severity = _worst(node.severity, f.severity)

        if f.plugin_id in _FOOTHOLD:
            add_edge(ENTRY_NODE_ID, h_node, EdgeKind.foothold, _FOOTHOLD[f.plugin_id], f)
        elif f.plugin_id in _CREDENTIAL_ACCESS:
            technique = _CREDENTIAL_ACCESS[f.plugin_id]
            c_node = cred_node(host, technique)
            nodes[c_node].severity = _worst(nodes[c_node].severity, f.severity)
            add_edge(h_node, c_node, EdgeKind.credential_access, technique, f)
        elif f.plugin_id in _LATERAL:
            # Lateral movement needs a credential to move *with*, and it has to
            # come from somewhere other than the host being moved to — otherwise
            # the edge is a self-loop that never crosses between hosts.
            #
            # An authenticated finding on this host proves *some* credential works
            # here. Any credential discovered elsewhere in the scan is a candidate;
            # if none was discovered, the finding only fired because the operator
            # supplied credentials, so the route starts from that explicitly.
            technique = _LATERAL[f.plugin_id]
            lateral_findings.append((f, host, technique))
        elif f.plugin_id in _ESCALATION:
            technique = _ESCALATION[f.plugin_id]
            kind = (
                EdgeKind.domain_compromise
                if f.plugin_id in ("services.dcsync_check", "services.zerologon",
                                   "services.unconstrained_delegation", "services.adcs_enum")
                else EdgeKind.privilege_escalation
            )
            target = domain_node() if kind is EdgeKind.domain_compromise else h_node
            if target == h_node:
                # Privilege escalation on the host itself: represent it as a
                # self-raising step from any credential on that host, or from entry.
                creds = [n for n in nodes if n.startswith(f"cred:{host.id}:")]
                src = creds[0] if creds else ENTRY_NODE_ID
                if src != target:
                    add_edge(src, target, kind, technique, f)
            else:
                add_edge(h_node, target, kind, technique, f)
        elif f.plugin_id in _TRUST:
            add_edge(h_node, domain_node(), EdgeKind.lateral_movement, _TRUST[f.plugin_id], f)

    # Second pass: connect lateral movement now that every discovered credential
    # is known. A credential found on the same host is skipped — the edge has to
    # cross between hosts to be movement at all.
    for f, target_host, technique in lateral_findings:
        h_node = f"host:{target_host.id}"
        sources = [
            nid for nid, node in nodes.items()
            if node.kind is NodeKind.credential
            and node.meta.get("from_host") != target_host.ip
        ]
        if not sources:
            sources = [supplied_cred_node()]
        for src in sources:
            if src != h_node:
                add_edge(src, h_node, EdgeKind.lateral_movement, technique, f)

    # Third pass: credential reuse. A credential obtained on one host is worth
    # trying against every other host that will accept one — that is what lateral
    # movement *is*, and a graph that only shows demonstrated authentications
    # produces almost no paths on a real scan, which makes the feature useless.
    #
    # These edges are hypotheses, so they are marked inferred=True, priced well
    # above demonstrated steps, and only drawn where the target actually exposes
    # an authentication service this scan observed. The port evidence is real; the
    # reuse is the reasoned part, and it is labelled as such rather than blended
    # in with observations.
    if infer_credential_reuse:
        _add_reuse_edges(nodes, edges, hosts)

    edge_list = list(edges.values())
    paths = _rank_paths(nodes, edge_list, max_paths=max_paths)
    return AttackGraph(
        nodes=list(nodes.values()),
        edges=edge_list,
        paths=paths,
        chokepoints=_chokepoints(nodes, paths),
    )


def _objectives(nodes: dict[str, Node], edges: list[Edge]) -> set[str]:
    """Nodes worth reaching: domains, and anything reached by an escalation step."""
    out = {n.id for n in nodes.values() if n.kind is NodeKind.domain}
    out |= {e.target for e in edges if e.kind in _OBJECTIVE_EDGES}
    out.discard(ENTRY_NODE_ID)
    return out


def _rank_paths(
    nodes: dict[str, Node], edges: list[Edge], *, max_paths: int
) -> list[AttackPath]:
    """Cheapest-first route from the entry point to each objective.

    Dijkstra over attacker effort rather than BFS over hop count: the route a real
    attacker takes is the cheap one, which is often not the short one.
    """
    objectives = _objectives(nodes, edges)
    if not objectives:
        return []

    adjacency: dict[str, list[Edge]] = {}
    for e in edges:
        adjacency.setdefault(e.source, []).append(e)

    dist: dict[str, float] = {ENTRY_NODE_ID: 0.0}
    prev: dict[str, Edge] = {}
    queue: list[tuple[float, str]] = [(0.0, ENTRY_NODE_ID)]
    seen: set[str] = set()

    while queue:
        cost, node_id = heapq.heappop(queue)
        if node_id in seen:
            continue
        seen.add(node_id)
        for edge in adjacency.get(node_id, []):
            nxt = cost + edge.cost
            if nxt < dist.get(edge.target, float("inf")):
                dist[edge.target] = nxt
                prev[edge.target] = edge
                heapq.heappush(queue, (nxt, edge.target))

    paths: list[AttackPath] = []
    for objective in objectives:
        if objective not in prev and objective != ENTRY_NODE_ID:
            continue  # unreachable from the attacker's position — not a path
        chain: list[Edge] = []
        cursor = objective
        guard = 0
        while cursor in prev and guard < 64:
            edge = prev[cursor]
            chain.append(edge)
            cursor = edge.source
            guard += 1
        if not chain or cursor != ENTRY_NODE_ID:
            continue
        chain.reverse()
        severity = "info"
        for e in chain:
            severity = _worst(severity, e.severity)
        paths.append(
            AttackPath(
                nodes=[ENTRY_NODE_ID] + [e.target for e in chain],
                edges=chain,
                cost=round(dist[objective], 2),
                severity=severity,
                objective=nodes[objective].label,
            )
        )

    # Cheapest (easiest for the attacker) first; then worst severity; then shortest.
    paths.sort(key=lambda p: (p.cost, -_SEVERITY_RANK.get(p.severity, 0), p.length))
    return paths[:max_paths]


def _chokepoints(nodes: dict[str, Node], paths: list[AttackPath]) -> list[dict]:
    """Nodes that appear on the most distinct paths.

    This is the actionable output: fixing a chokepoint breaks every path through
    it, which is a different — and usually better — prioritisation than working
    down a list sorted by CVSS.
    """
    counts: dict[str, int] = {}
    for path in paths:
        # Skip the entry node: it is on every path by construction.
        for node_id in path.nodes[1:]:
            counts[node_id] = counts.get(node_id, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [
        {
            "node_id": node_id,
            "label": nodes[node_id].label,
            "kind": nodes[node_id].kind.value,
            "path_count": count,
        }
        for node_id, count in ranked
        if count > 1
    ]
