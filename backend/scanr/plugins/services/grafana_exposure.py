from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class GrafanaExposurePlugin(PluginBase):
    id = "services.grafana_exposure"
    name = "Grafana Exposure"
    description = "Detect exposed Grafana login or anonymous access"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [3000]

    async def check(self, context, host):
        for port in _open(host, {3000}):
            got = await _http_get(context, host.ip, port, "/api/health")
            if got and got[1].status_code == 200 and "grafana" in got[1].text.lower():
                anon = await _http_get(context, host.ip, port, "/api/search")
                sev = Severity.high if anon and anon[1].status_code == 200 and anon[1].text.strip().startswith("[") else Severity.medium
                return [_finding(self.id, sev, "Grafana Exposed", "Grafana is reachable and may allow anonymous dashboard enumeration.", f"{got[0]} returned Grafana health; anonymous_search={sev == Severity.high}", "Disable anonymous access, enforce SSO/MFA, and restrict Grafana to trusted networks.", port)]
        return []

