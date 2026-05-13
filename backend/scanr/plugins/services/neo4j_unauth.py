from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class Neo4jUnauthPlugin(PluginBase):
    id = "services.neo4j_unauth"
    name = "Neo4j Unauthenticated Access"
    description = "Detect Neo4j HTTP API unauthenticated access"
    category = PluginCategory.services
    severity = Severity.high
    ports = [7474, 7473]

    async def check(self, context, host):
        for port in _open(host, set(self.ports)):
            got = await _http_get(context, host.ip, port, "/db/data/")
            if got and got[1].status_code == 200 and "neo4j" in got[1].text.lower():
                return [_finding(self.id, Severity.high, "Neo4j HTTP API Accessible", "Neo4j HTTP API is accessible and may allow unauthenticated graph access depending on auth configuration.", f"{got[0]} returned Neo4j API data", "Enable Neo4j authentication and restrict browser/API ports.", port)]
        return []

