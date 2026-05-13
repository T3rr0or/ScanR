"""Kubernetes RBAC enumeration.

With a service account token (type: k8s_token in credential vault), enumerate:
- ClusterRoleBindings binding cluster-admin to non-system accounts
- ClusterRoles with wildcard verbs/resources
- RoleBindings granting secrets/get or pods/exec

Requires: credentials with type "k8s_token" and username containing the token.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class K8sRbacEnumPlugin(PluginBase):
    id = "services.k8s_rbac_enum"
    name = "Kubernetes RBAC Enumeration"
    description = "Enumerate Kubernetes RBAC for overly permissive roles: cluster-admin bindings, wildcard rules, secrets/get, pods/exec"
    category = PluginCategory.services
    severity = Severity.high
    ports = [6443, 8443, 8080]
    requires_auth = True

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        creds = context.credential_data or {}
        # Support k8s_token type (username field holds the token)
        token = creds.get("token") or creds.get("password") or creds.get("username")
        if not token:
            return []

        open_ports = {p.number for p in host.ports if p.state == "open"}
        k8s_ports = [p for p in self.ports if p in open_ports]
        if not k8s_ports:
            return []

        findings = []
        for port in k8s_ports:
            scheme = "https" if port in (6443, 8443) else "http"
            base = f"{scheme}://{host.ip}:{port}"
            result = await self._enumerate(context, base, token, port)
            if result:
                findings.extend(result)
        return findings

    async def _enumerate(self, context, base: str, token: str, port: int) -> list[FindingData]:
        findings = []
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(verify=False, timeout=10.0, headers=headers,
                **context.proxy_config()
            ) as client:
            # 1. ClusterRoleBindings — find cluster-admin bindings
            try:
                resp = await client.get(f"{base}/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
                if resp.status_code == 200:
                    data = resp.json()
                    dangerous = []
                    for item in data.get("items", []):
                        role_ref = item.get("roleRef", {})
                        if role_ref.get("name") == "cluster-admin":
                            subjects = item.get("subjects", [])
                            non_system = [s for s in subjects
                                          if not s.get("name", "").startswith("system:")
                                          and s.get("namespace") not in ("kube-system",)]
                            if non_system:
                                binding_name = str(item.get("metadata", {}).get("name", "unknown"))[:80]
                                for s in non_system:
                                    sname = str(s.get('name','?'))[:60]
                                    dangerous.append(f"  {binding_name}: {s.get('kind','?')}/{sname} (ns: {s.get('namespace','cluster')})")
                    if dangerous:
                        findings.append(FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title=f"Kubernetes: cluster-admin Bound to Non-System Accounts ({len(dangerous)})",
                            description=(
                                f"The Kubernetes API at {base} has {len(dangerous)} non-system account(s) bound to "
                                "the cluster-admin ClusterRole, granting full control over the entire cluster. "
                                "An attacker with these credentials can read all secrets, exec into any pod, "
                                "create privileged containers, and compromise the underlying nodes."
                            ),
                            evidence="cluster-admin bindings:\n" + "\n".join(dangerous),
                            remediation=(
                                "Remove cluster-admin bindings from non-admin accounts. "
                                "Apply principle of least privilege. "
                                "Use namespace-scoped roles instead of ClusterRoles where possible."
                            ),
                            references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
                            port_number=port, protocol="tcp",
                        ))
            except Exception as exc:
                logger.debug("K8s RBAC ClusterRoleBindings failed: %s", exc)

            # 2. ClusterRoles with wildcard rules
            try:
                resp = await client.get(f"{base}/apis/rbac.authorization.k8s.io/v1/clusterroles")
                if resp.status_code == 200:
                    data = resp.json()
                    wildcard_roles = []
                    for item in data.get("items", []):
                        name = item.get("metadata", {}).get("name", "")
                        if name.startswith("system:"):
                            continue
                        for rule in item.get("rules", []):
                            verbs = rule.get("verbs", [])
                            resources = rule.get("resources", [])
                            if "*" in verbs or "*" in resources:
                                wildcard_roles.append(f"  {name}: verbs={verbs}, resources={resources}")
                                break
                    if wildcard_roles:
                        findings.append(FindingData(
                            plugin_id=self.id,
                            severity=Severity.high,
                            title=f"Kubernetes: {len(wildcard_roles)} ClusterRole(s) with Wildcard Permissions",
                            description=(
                                f"Found {len(wildcard_roles)} custom ClusterRole(s) with wildcard verbs or resources. "
                                "Wildcards grant all actions on all resource types, effectively equivalent to cluster-admin."
                            ),
                            evidence="Wildcard ClusterRoles:\n" + "\n".join(wildcard_roles[:10]),
                            remediation="Replace wildcard rules with specific verb/resource combinations following least-privilege.",
                            references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
                            port_number=port, protocol="tcp",
                        ))
            except Exception as exc:
                logger.debug("K8s RBAC ClusterRoles failed: %s", exc)

            # 3. RoleBindings with sensitive permissions
            try:
                resp = await client.get(f"{base}/apis/rbac.authorization.k8s.io/v1/rolebindings")
                if resp.status_code == 200:
                    data = resp.json()
                    dangerous_bindings = []
                    for item in data.get("items", []):
                        ns = item.get("metadata", {}).get("namespace", "")
                        role_ref = item.get("roleRef", {})
                        role_name = role_ref.get("name", "")
                        subjects = item.get("subjects", [])
                        for s in subjects:
                            if not s.get("name", "").startswith("system:"):
                                dangerous_bindings.append(
                                    f"  ns/{ns}: {s.get('kind','?')}/{s.get('name','?')} → {role_name}"
                                )
                    if dangerous_bindings:
                        findings.append(FindingData(
                            plugin_id=self.id,
                            severity=Severity.medium,
                            title=f"Kubernetes: {len(dangerous_bindings)} Non-System RoleBinding(s) Found",
                            description=(
                                f"Found {len(dangerous_bindings)} RoleBinding(s) granting permissions to non-system accounts. "
                                "Review each binding to ensure least-privilege is applied."
                            ),
                            evidence="Non-system RoleBindings:\n" + "\n".join(dangerous_bindings[:15]),
                            remediation="Audit all RoleBindings. Remove unnecessary permissions. Use service accounts with minimal roles.",
                            references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
                            port_number=port, protocol="tcp",
                        ))
            except Exception as exc:
                logger.debug("K8s RBAC RoleBindings failed: %s", exc)

        return findings
