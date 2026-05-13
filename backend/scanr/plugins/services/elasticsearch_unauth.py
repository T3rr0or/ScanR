from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class ElasticsearchUnauthPlugin(PluginBase):
    id = "services.elasticsearch_unauth"
    name = "Elasticsearch Unauthenticated Access"
    description = "Detect Elasticsearch instances accessible without authentication"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [9200, 9300]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in (9200, 9300):
                continue
            result = await self._probe(host.ip, port.number, context)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, ip: str, port: int, context: "ScanContext") -> FindingData | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, **context.proxy_config()) as client:
                resp = await client.get(f"http://{ip}:{port}/")
                if resp.status_code != 200:
                    return None
                data = resp.json()
                if "cluster_name" not in data:
                    return None

                cluster_name = data.get("cluster_name", "unknown")
                version = data.get("version", {}).get("number", "unknown")

                # Try to list indices
                indices_resp = await client.get(f"http://{ip}:{port}/_cat/indices?v")
                indices_info = ""
                if indices_resp.status_code == 200:
                    lines = indices_resp.text.strip().splitlines()
                    index_count = max(0, len(lines) - 1)
                    indices_info = f" — {index_count} indices found"

                return FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="Elasticsearch Unauthenticated Access",
                    description=(
                        f"Elasticsearch cluster '{cluster_name}' (v{version}) is accessible without authentication. "
                        f"An attacker can read, modify, or delete all indexed data{indices_info}."
                    ),
                    evidence=f"GET http://{ip}:{port}/ → cluster_name={cluster_name}, version={version}{indices_info}",
                    remediation=(
                        "Enable Elasticsearch security (X-Pack). Configure authentication and TLS. "
                        "Bind to localhost or use firewall rules to restrict access to port 9200."
                    ),
                    references=[
                        "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
                    ],
                    port_number=port,
                    protocol="tcp",
                )
        except Exception:
            pass
        return None
