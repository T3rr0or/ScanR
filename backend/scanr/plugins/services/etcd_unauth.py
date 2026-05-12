from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class EtcdUnauthPlugin(PluginBase):
    id = "services.etcd_unauth"
    name = "etcd Unauthenticated Access"
    description = "Detect unauthenticated etcd API access exposing cluster configuration and secrets"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [2379, 2380]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in (2379, 2380) or port.state != "open":
                continue
            result = await self._probe(host.ip, port.number)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, ip: str, port: int) -> FindingData | None:
        for scheme in ("https", "http"):
            base = f"{scheme}://{ip}:{port}"
            try:
                async with httpx.AsyncClient(verify=False, timeout=6.0, **context.proxy_config()) as client:
                    evidence_parts = []

                    try:
                        r = await client.get(f"{base}/v2/keys")
                        if r.status_code == 200 and (
                            "nodes" in r.text or "dir" in r.text or r.text.strip().startswith("{")
                        ):
                            evidence_parts.append(f"GET /v2/keys → {r.status_code} ({len(r.text)} bytes)")
                    except Exception:
                        pass

                    try:
                        r = await client.get(f"{base}/v3/members")
                        if r.status_code == 200 and "members" in r.text:
                            evidence_parts.append(f"GET /v3/members → {r.status_code}")
                    except Exception:
                        pass

                    is_etcd = False
                    try:
                        r = await client.get(f"{base}/health")
                        if r.status_code == 200 and ("health" in r.text or "etcd" in r.text.lower()):
                            is_etcd = True
                            evidence_parts.append(f"GET /health → {r.status_code}")
                    except Exception:
                        pass

                    if not evidence_parts or not is_etcd:
                        continue  # try next scheme

                    try:
                        r = await client.get(f"{base}/v2/keys/registry/secrets")
                        if r.status_code == 200:
                            evidence_parts.append(
                                "GET /v2/keys/registry/secrets → 200 (Kubernetes secrets accessible!)"
                            )
                    except Exception:
                        pass

                    return FindingData(
                        plugin_id=self.id,
                        severity=Severity.critical,
                        title=f"etcd Unauthenticated Access ({scheme.upper()})",
                        description=(
                            f"The etcd cluster at {ip}:{port} ({scheme}) is accessible without authentication. "
                            "etcd stores all Kubernetes cluster state and secrets. "
                            "An attacker can read service account tokens, TLS certificates, and all "
                            "application secrets stored as Kubernetes Secrets."
                        ),
                        evidence="\n".join(evidence_parts),
                        remediation=(
                            "Enable etcd client certificate authentication. "
                            "Restrict etcd ports (2379, 2380) to control-plane nodes only via firewall. "
                            "Rotate all credentials if exposed."
                        ),
                        references=[
                            "https://etcd.io/docs/v3.5/op-guide/security/",
                            "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
                        ],
                        port_number=port,
                        protocol="tcp",
                    )
            except Exception as exc:
                logger.debug("etcd probe %s %s:%d: %s", scheme, ip, port, exc)
        return None
