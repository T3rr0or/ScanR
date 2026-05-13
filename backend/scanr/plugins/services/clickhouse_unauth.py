from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class ClickHouseUnauthPlugin(PluginBase):
    id = "services.clickhouse_unauth"
    name = "ClickHouse Unauthenticated Access"
    description = "Detect unauthenticated ClickHouse HTTP query access"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [8123, 9000]

    async def check(self, context, host):
        for port in _open(host, {8123}):
            got = await _http_get(context, host.ip, port, "/?query=SELECT%201")
            if got and got[1].status_code == 200 and got[1].text.strip() == "1":
                return [_finding(self.id, Severity.critical, "ClickHouse Query API Unauthenticated", "ClickHouse executed SELECT 1 without authentication.", f"{got[0]} -> 1", "Require ClickHouse authentication/TLS and restrict database ports.", port)]
        if 9000 in _open(host, {9000}):
            return [_finding(self.id, Severity.medium, "ClickHouse Native Port Exposed", "ClickHouse native TCP port is reachable; unauthenticated access should be manually verified.", "TCP/9000 open", "Require authentication/TLS and restrict ClickHouse native port.", 9000)]
        return []

