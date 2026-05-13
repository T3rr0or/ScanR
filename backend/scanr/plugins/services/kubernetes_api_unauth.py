from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

K8S_PORTS = [6443, 8443, 8080, 10250, 10255]


class KubernetesApiUnauthPlugin(PluginBase):
    id = "services.kubernetes_api_unauth"
    name = "Kubernetes API Unauthenticated Access"
    description = "Detect exposed Kubernetes API server with anonymous or unauthenticated access"
    category = PluginCategory.services
    severity = Severity.critical
    ports = K8S_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in K8S_PORTS or port.state != "open":
                continue
            result = await self._probe(context, host.ip, port.number)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, context, ip: str, port: int) -> FindingData | None:
        scheme = "https" if port in (6443, 8443, 10250) else "http"

        # kubelet read-only port (10255)
        if port == 10255:
            return await self._probe_kubelet_readonly(ip, port)

        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, **context.proxy_config()) as client:
                resp = await client.get(f"{scheme}://{ip}:{port}/api")
                if resp.status_code == 200:
                    data = resp.json()
                    if "versions" in data or "serverAddressByClientCIDRs" in data:
                        return FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title="Kubernetes API Server — Anonymous Access Allowed",
                            description=(
                                f"The Kubernetes API server on port {port} is accessible without authentication. "
                                "Anonymous access is enabled. An attacker can enumerate cluster resources, "
                                "create pods, and potentially gain cluster-admin privileges."
                            ),
                            evidence=f"GET {scheme}://{ip}:{port}/api → HTTP 200 with API version list",
                            remediation=(
                                "Disable anonymous authentication: --anonymous-auth=false. "
                                "Ensure RBAC is enabled and no ClusterRoleBindings grant anonymous access. "
                                "Restrict API server access via network policy or firewall."
                            ),
                            references=[
                                "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests",
                                "https://attack.mitre.org/techniques/T1613/",
                            ],
                            port_number=port,
                            protocol="tcp",
                        )
                elif resp.status_code in (401, 403):
                    # Auth required — report as informational (server found, auth enforced)
                    return FindingData(
                        plugin_id=self.id,
                        severity=Severity.info,
                        title="Kubernetes API Server Detected",
                        description=(
                            f"A Kubernetes API server was detected on port {port}. "
                            "Authentication is enforced (HTTP {resp.status_code})."
                        ),
                        evidence=f"GET {scheme}://{ip}:{port}/api → HTTP {resp.status_code}",
                        remediation="Verify RBAC policies and ensure least-privilege access.",
                        port_number=port,
                        protocol="tcp",
                    )
        except Exception:
            pass
        return None

    async def _probe_kubelet_readonly(self, ip: str, port: int) -> FindingData | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, **context.proxy_config()) as client:
                resp = await client.get(f"http://{ip}:{port}/pods")
                if resp.status_code == 200 and "items" in resp.text:
                    return FindingData(
                        plugin_id=self.id,
                        severity=Severity.high,
                        title="Kubernetes Kubelet Read-Only Port Exposed",
                        description=(
                            "The Kubelet read-only port (10255) is accessible without authentication. "
                            "An attacker can enumerate running pods, container images, and node information."
                        ),
                        evidence=f"GET http://{ip}:{port}/pods → HTTP 200 with pod list",
                        remediation=(
                            "Disable the Kubelet read-only port: --read-only-port=0. "
                            "Use the authenticated port (10250) with proper certificates instead."
                        ),
                        port_number=port,
                        protocol="tcp",
                    )
        except Exception:
            pass
        return None
