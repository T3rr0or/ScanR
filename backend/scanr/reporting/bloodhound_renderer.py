"""BloodHound-compatible JSON export.

Exports domain objects (computers, users, groups), relationships
(memberOf, AdminTo, HasSession, TrustedBy), and ACL abuse edges
in BloodHound JSON format for ingestion by BloodHound CE.

Reference: https://github.com/SpecterOps/BloodHound/wiki/Data-Collection
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanr.models import Finding, Scan
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


async def render_bloodhound_json(
    scan: "Scan",
    findings: list["Finding"],
    db: "AsyncSession",
    output_path: Path,
) -> Path:
    """Generate BloodHound-compatible JSON from scan findings.

    Maps ScanR findings to BloodHound node/edge types:
      - AD computer findings → Computer nodes
      - User enumeration → User nodes
      - SMB admin shares → AdminTo edges
      - Kerberos delegation → AllowedToDelegate edges
      - Trust enumeration → TrustedBy edges
      - Group enumeration → Group nodes + MemberOf edges
    """
    nodes: dict[str, list[dict]] = {
        "computers": [],
        "users": [],
        "groups": [],
        "domains": [],
        "ous": [],
        "gpos": [],
        "containers": [],
    }
    edges: list[dict] = []

    domain_name = _extract_domain_name(scan)
    domain_sid = _domain_sid_from_findings(findings) or f"S-1-5-21-{abs(hash(domain_name)) & 0xFFFFFFFF}"

    # Add domain node
    domain_node = {
        "ObjectIdentifier": domain_sid,
        "Properties": {
            "name": f"{domain_name}@SCANR",
            "domain": domain_name,
            "distinguishedname": f"DC={domain_name.replace('.', ',DC=')}",
            "domainsid": domain_sid,
            "highvalue": False,
            "description": f"Domain discovered by ScanR scan: {scan.name}",
        },
        "Aces": [],
        "ObjectType": "Domain",
        "IsDeleted": False,
        "IsACLProtected": False,
        "Collected": True,
    }
    nodes["domains"].append(domain_node)

    for finding in findings:
        plugin_id = finding.plugin_id
        evidence = finding.evidence or ""
        title = finding.title or ""

        # Trust enumeration → TrustedBy edges
        if plugin_id == "services.trust_enum" or "trust" in plugin_id:
            trusts = _parse_trust_finding(evidence, domain_name, domain_sid)
            nodes["domains"].extend(trusts["nodes"])
            edges.extend(trusts["edges"])

        # Admin share access → AdminTo edges
        if plugin_id == "services.admin_share_access" or "admin share" in title.lower():
            admin_edge = _parse_admin_access(evidence, domain_name)
            if admin_edge:
                edges.append(admin_edge)

        # Kerberos delegation → AllowedToDelegate edges
        if "delegation" in plugin_id or "unconstrained" in plugin_id:
            delegation_edges = _parse_delegation(evidence, domain_name)
            edges.extend(delegation_edges)

        # AS-REP roastable / Kerberoastable → User nodes with flag
        if plugin_id in ("services.asreproastable", "services.kerberoastable"):
            user_nodes = _parse_roastable_users(evidence, domain_name, finding)
            nodes["users"].extend(user_nodes)

        # SMB share enum → Computer nodes
        if plugin_id == "services.smb_share_enum" or "smb_authenticated" in plugin_id:
            comp_nodes = _parse_computer_from_smb(evidence, domain_name, finding.host_id)
            nodes["computers"].extend(comp_nodes)

        # DCSync privilege → high-value user/group
        if plugin_id == "services.dcsync_check":
            dcsync_edges = _parse_dcsync(evidence, domain_name, finding)
            edges.extend(dcsync_edges)

        # gMSA readable → User nodes
        if plugin_id == "services.gmsa_readable":
            gmsa_nodes = _parse_gmsa(evidence, domain_name, finding)
            nodes["users"].extend(gmsa_nodes)

        # LDAP user enum → User nodes
        if plugin_id == "services.ldap_user_enum" or "netbios_info" in plugin_id:
            user_nodes = _parse_ldap_users(evidence, domain_name)
            nodes["users"].extend(user_nodes)

        # SMB null session / open shares → computer info
        if plugin_id in ("services.smb_null_session", "services.zerologon"):
            comp = _parse_null_session(evidence, domain_name)
            if comp:
                nodes["computers"].append(comp)

    # Deduplicate nodes by ObjectIdentifier
    for node_type in nodes:
        seen: set = set()
        deduped: list[dict] = []
        for node in nodes[node_type]:
            oid = node.get("ObjectIdentifier", "")
            if oid not in seen:
                seen.add(oid)
                deduped.append(node)
        nodes[node_type] = deduped

    # Build BloodHound-format JSON
    bh_data: dict[str, Any] = {
        "data": [],
        "meta": {
            "methods": 0,
            "type": "users",
            "version": 5,
            "count": sum(len(v) for v in nodes.values()),
        },
    }

    # Users array
    if nodes["users"]:
        bh_data["data"].append({
            "Users": {
                "Props": {n["ObjectIdentifier"]: n["Properties"] for n in nodes["users"]},
                "ObjectIdentifiers": [n["ObjectIdentifier"] for n in nodes["users"]],
                "Aces": {n["ObjectIdentifier"]: n.get("Aces", []) for n in nodes["users"]},
                "CollectionMethods": ["ScanR"],
            }
        })

    # Computers array
    if nodes["computers"]:
        bh_data["data"].append({
            "Computers": {
                "Props": {n["ObjectIdentifier"]: n["Properties"] for n in nodes["computers"]},
                "ObjectIdentifiers": [n["ObjectIdentifier"] for n in nodes["computers"]],
                "Aces": {n["ObjectIdentifier"]: n.get("Aces", []) for n in nodes["computers"]},
                "CollectionMethods": ["ScanR"],
            }
        })

    # Groups array
    if nodes["groups"]:
        bh_data["data"].append({
            "Groups": {
                "Props": {n["ObjectIdentifier"]: n["Properties"] for n in nodes["groups"]},
                "ObjectIdentifiers": [n["ObjectIdentifier"] for n in nodes["groups"]],
                "Aces": {n["ObjectIdentifier"]: n.get("Aces", []) for n in nodes["groups"]},
                "CollectionMethods": ["ScanR"],
            }
        })

    # Domains array
    bh_data["data"].append({
        "Domains": {
            "Props": {n["ObjectIdentifier"]: n["Properties"] for n in nodes["domains"]},
            "ObjectIdentifiers": [n["ObjectIdentifier"] for n in nodes["domains"]],
            "CollectionMethods": ["ScanR"],
        }
    })

    if edges:
        bh_data["data"].append({"Edges": edges})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bh_data, indent=2))
    logger.info("BloodHound JSON exported: %s (%d nodes, %d edges)",
                 output_path, sum(len(v) for v in nodes.values()), len(edges))
    return output_path


def _extract_domain_name(scan: "Scan") -> str:
    """Extract domain name from scan name or profile."""
    if scan.profile_json:
        try:
            pj = json.loads(scan.profile_json) if isinstance(scan.profile_json, str) else scan.profile_json
            if pj.get("domain_name"):
                return pj["domain_name"]
        except Exception:
            pass
    # Infer from targets
    return "unknown.domain"


def _domain_sid_from_findings(findings: list["Finding"]) -> str | None:
    """Try to extract domain SID from finding evidence."""
    import re
    sid_pattern = re.compile(r"S-1-5-21-\d+-\d+-\d+")
    for f in findings:
        match = sid_pattern.search(f.evidence or "")
        if match:
            return match.group(0)
    return None


def _parse_trust_finding(evidence: str, domain: str, domain_sid: str) -> dict:
    """Parse trust enumeration evidence into BloodHound TrustedBy edges."""
    import re
    nodes: list[dict] = []
    edges: list[dict] = []

    # Parse trust lines: target — type=X, dir=Y
    trust_lines = re.findall(
        r"(\S+)\s*[—-]\s*type=(\S+),\s*dir=(\S+)",
        evidence,
    )
    for target, trust_type, direction in trust_lines:
        target_domain = target.rstrip("$")
        target_sid = f"S-1-5-21-{abs(hash(target_domain)) & 0xFFFFFFFF}"
        nodes.append({
            "ObjectIdentifier": target_sid,
            "Properties": {
                "name": target_domain,
                "domain": target_domain,
                "domainsid": target_sid,
                "highvalue": "forest" in trust_type.lower(),
            },
            "Aces": [],
            "ObjectType": "Domain",
            "IsDeleted": False,
            "IsACLProtected": False,
        })
        edges.append({
            "SourceId": domain_sid,
            "TargetId": target_sid,
            "EdgeType": "TrustedBy",
            "Properties": {
                "trusttype": trust_type,
                "trustdirection": direction,
                "isacl": False,
            },
        })

    return {"nodes": nodes, "edges": edges}


def _parse_admin_access(evidence: str, domain: str) -> dict | None:
    """Parse admin share access into AdminTo edge."""
    import re
    hostname = ""
    host_match = re.search(r"Admin access confirmed on (\S+)", evidence)
    if host_match:
        hostname = host_match.group(1)
    elif "ADMIN$" in evidence:
        parts = evidence.split("\n")
        for p in parts:
            if "\\\\" in p:
                hostname = p.split("\\\\")[1].split("\\")[0]
                break
    if not hostname:
        return None

    return {
        "SourceId": f"S-1-5-21-{abs(hash('scanr_user')) & 0xFFFFFFFF}",
        "TargetId": f"S-1-5-21-{abs(hash(hostname)) & 0xFFFFFFFF}",
        "EdgeType": "AdminTo",
        "Properties": {"isacl": False},
    }


def _parse_delegation(evidence: str, domain: str) -> list[dict]:
    """Parse delegation findings into AllowedToDelegate edges."""
    import re
    edges: list[dict] = []
    hostnames = re.findall(r"(\S+)\s+has (?:unconstrained|constrained) delegation", evidence)
    for hostname in hostnames:
        edges.append({
            "SourceId": f"S-1-5-21-{abs(hash(hostname)) & 0xFFFFFFFF}",
            "TargetId": f"S-1-5-21-{abs(hash('any')) & 0xFFFFFFFF}",
            "EdgeType": "AllowedToDelegate",
            "Properties": {"isacl": False},
        })
    return edges


def _parse_roastable_users(evidence: str, domain: str, finding: "Finding") -> list[dict]:
    """Parse AS-REP/Kerberoastable users into User nodes."""
    users: list[dict] = []
    for line in (evidence or "").splitlines():
        line = line.strip()
        if not line or ":" in line:
            continue
        if "@" in line or "\\" in line:
            username = line.split("@")[0].split("\\")[-1].strip()
            oid = f"S-1-5-21-{abs(hash(f'{domain}\\{username}')) & 0xFFFFFFFF}"
            users.append({
                "ObjectIdentifier": oid,
                "Properties": {
                    "name": f"{username}@{domain}",
                    "domain": domain,
                    "samaccountname": username,
                    "has sid history": False,
                    "dontreqpreauth": finding.plugin_id == "services.asreproastable",
                    "hasspn": finding.plugin_id == "services.kerberoastable",
                    "highvalue": finding.severity == "critical",
                },
                "Aces": [],
                "ObjectType": "User",
                "IsDeleted": False,
                "IsACLProtected": False,
            })
    return users


def _parse_computer_from_smb(evidence: str, domain: str, host_id: str | None) -> list[dict]:
    """Parse SMB share enumeration into Computer nodes."""
    comps: list[dict] = []
    # Extract computer names from SMB evidence
    import re
    names = re.findall(r"\\\\?(\S+)\\", evidence)
    for name in set(names):
        clean = name.split(".")[0]  # strip FQDN
        oid = f"S-1-5-21-{abs(hash(f'{domain}\\{clean}')) & 0xFFFFFFFF}"
        comps.append({
            "ObjectIdentifier": oid,
            "Properties": {
                "name": f"{clean}.{domain}",
                "domain": domain,
                "samaccountname": f"{clean}$",
                "operatingsystem": "",
                "haslaps": False,
                "highvalue": False,
            },
            "Aces": [],
            "ObjectType": "Computer",
            "IsDeleted": False,
            "IsACLProtected": False,
        })
    return comps


def _parse_dcsync(evidence: str, domain: str, finding: "Finding") -> list[dict]:
    """Parse DCSync privilege into edges."""
    import re
    edges: list[dict] = []
    usernames = re.findall(r"(\S+) has DCSync", evidence)
    for username in usernames:
        user_sid = f"S-1-5-21-{abs(hash(f'{domain}\\{username}')) & 0xFFFFFFFF}"
        domain_sid = f"S-1-5-21-{abs(hash(domain)) & 0xFFFFFFFF}"
        edges.append({
            "SourceId": user_sid,
            "TargetId": domain_sid,
            "EdgeType": "DCSync",
            "Properties": {"isacl": True},
        })
    return edges


def _parse_gmsa(evidence: str, domain: str, finding: "Finding") -> list[dict]:
    """Parse gMSA readable accounts into User nodes."""
    import re
    users: list[dict] = []
    names = re.findall(r"gMSA account (\S+) readable", evidence)
    for name in names:
        oid = f"S-1-5-21-{abs(hash(f'{domain}\\{name}')) & 0xFFFFFFFF}"
        users.append({
            "ObjectIdentifier": oid,
            "Properties": {
                "name": f"{name}@{domain}",
                "domain": domain,
                "samaccountname": name,
                "highvalue": True,
            },
            "Aces": [],
            "ObjectType": "User",
            "IsDeleted": False,
            "IsACLProtected": False,
        })
    return users


def _parse_ldap_users(evidence: str, domain: str) -> list[dict]:
    """Parse LDAP/NetBIOS enumeration into User nodes."""
    users: list[dict] = []
    for line in (evidence or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("Host:"):
            # Simple username extraction
            username = line.split()[0] if line.split() else ""
            if username and len(username) > 1 and len(username) < 50:
                oid = f"S-1-5-21-{abs(hash(f'{domain}\\{username}')) & 0xFFFFFFFF}"
                users.append({
                    "ObjectIdentifier": oid,
                    "Properties": {
                        "name": f"{username}@{domain}",
                        "domain": domain,
                        "samaccountname": username,
                        "highvalue": "admin" in username.lower(),
                    },
                    "Aces": [],
                    "ObjectType": "User",
                    "IsDeleted": False,
                    "IsACLProtected": False,
                })
    return users[:100]  # cap at 100 users


def _parse_null_session(evidence: str, domain: str) -> dict | None:
    """Parse null session finding to flag vulnerable DC."""
    hostname_match = __import__("re").search(r"(\S+) — NULL session", evidence)
    if not hostname_match:
        return None
    hostname = hostname_match.group(1).split(".")[0]
    oid = f"S-1-5-21-{abs(hash(f'{domain}\\{hostname}')) & 0xFFFFFFFF}"
    return {
        "ObjectIdentifier": oid,
        "Properties": {
            "name": f"{hostname}.{domain}",
            "domain": domain,
            "samaccountname": f"{hostname}$",
            "operatingsystem": "",
            "haslaps": False,
            "highvalue": True,
        },
        "Aces": [],
        "ObjectType": "Computer",
        "IsDeleted": False,
        "IsACLProtected": False,
    }
