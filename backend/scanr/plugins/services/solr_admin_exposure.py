from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class SolrAdminExposurePlugin(PluginBase):
    id = "services.solr_admin_exposure"
    name = "Apache Solr Admin Exposure"
    description = "Detect exposed Solr admin API"
    category = PluginCategory.services
    severity = Severity.high
    ports = [8983]

    async def check(self, context, host):
        for port in _open(host, {8983}):
            got = await _http_get(context, host.ip, port, "/solr/admin/info/system?wt=json")
            if got and got[1].status_code == 200 and "lucene" in got[1].text.lower():
                return [_finding(self.id, Severity.high, "Solr Admin API Exposed", "Apache Solr admin API is reachable and can expose system/configuration details.", f"{got[0]} returned Solr system info", "Enable Solr authentication/authorization and restrict admin endpoints.", port)]
        return []

