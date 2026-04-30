from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 5000, 9000]

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphiql", "/gql", "/api/gql", "/query"]

INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}'


class GraphQLIntrospectionPlugin(PluginBase):
    id = "web.graphql_introspection"
    name = "GraphQL Introspection Enabled"
    description = "Detect exposed GraphQL endpoints with introspection enabled"
    category = PluginCategory.web
    severity = Severity.info
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            finding = await self._probe(host.ip, port.number, scheme)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, ip: str, port: int, scheme: str) -> FindingData | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
                for path in GRAPHQL_PATHS:
                    url = f"{scheme}://{ip}:{port}{path}"
                    try:
                        resp = await client.post(
                            url,
                            content=INTROSPECTION_QUERY,
                            headers={"Content-Type": "application/json"},
                        )
                        if resp.status_code == 200 and "__schema" in resp.text:
                            # Count exposed types
                            import json
                            try:
                                data = resp.json()
                                types = data.get("data", {}).get("__schema", {}).get("types", [])
                                type_count = len(types)
                            except Exception:
                                type_count = 0

                            return FindingData(
                                plugin_id=self.id,
                                severity=Severity.info,
                                title="GraphQL Introspection Enabled",
                                description=(
                                    f"The GraphQL endpoint at {path} has introspection enabled, "
                                    f"exposing the full API schema ({type_count} types). "
                                    "This allows attackers to enumerate all queries, mutations, and types."
                                ),
                                evidence=f"POST {url} → __schema in response ({type_count} types exposed)",
                                remediation=(
                                    "Disable introspection in production environments. "
                                    "Most GraphQL libraries support a flag to disable it."
                                ),
                                references=[
                                    "https://graphql.org/learn/introspection/",
                                    "https://owasp.org/www-project-api-security/",
                                ],
                                port_number=port,
                                protocol="tcp",
                            )
                    except Exception:
                        continue
        except Exception:
            pass
        return None
