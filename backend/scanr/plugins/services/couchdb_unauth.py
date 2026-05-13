from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class CouchDbUnauthPlugin(PluginBase):
    id = "services.couchdb_unauth"
    name = "CouchDB Unauthenticated Access"
    description = "Detect unauthenticated CouchDB API access"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [5984]

    async def check(self, context, host):
        for port in _open(host, {5984}):
            got = await _http_get(context, host.ip, port, "/_all_dbs")
            if got and got[1].status_code == 200 and got[1].text.strip().startswith("["):
                return [_finding(self.id, Severity.critical, "CouchDB Databases Listed Without Authentication", "CouchDB exposes database names without authentication.", f"{got[0]} returned database list", "Enable CouchDB admin party protection/authentication and restrict port 5984.", port)]
        return []

