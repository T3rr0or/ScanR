from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class OracleTnsCheckPlugin(PluginBase):
    id = "services.oracle_tns_check"
    name = "Oracle TNS Listener Exposure"
    description = "Detect exposed Oracle TNS listeners"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [1521, 1522]

    async def check(self, context, host):
        for port in _open(host, set(self.ports)):
            return [_finding(self.id, Severity.medium, "Oracle TNS Listener Exposed", "Oracle TNS listener is reachable and may disclose service names or allow password attacks if not restricted.", f"TCP/{port} open", "Restrict Oracle listener access and disable remote listener administration.", port)]
        return []

