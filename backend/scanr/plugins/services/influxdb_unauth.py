from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class InfluxDbUnauthPlugin(PluginBase):
    id = "services.influxdb_unauth"
    name = "InfluxDB Unauthenticated Access"
    description = "Detect unauthenticated InfluxDB endpoints"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [8086]

    async def check(self, context, host):
        for port in _open(host, {8086}):
            got = await _http_get(context, host.ip, port, "/query?q=SHOW%20DATABASES")
            if got and got[1].status_code == 200 and "results" in got[1].text.lower():
                return [_finding(self.id, Severity.critical, "InfluxDB Query API Unauthenticated", "InfluxDB accepted a SHOW DATABASES query without authentication.", f"{got[0]} returned results", "Enable authentication/TLS and restrict InfluxDB HTTP API.", port)]
        return []

