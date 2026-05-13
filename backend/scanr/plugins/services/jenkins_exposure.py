from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class JenkinsExposurePlugin(PluginBase):
    id = "services.jenkins_exposure"
    name = "Jenkins Exposure"
    description = "Detect exposed Jenkins endpoints and anonymous read access"
    category = PluginCategory.services
    severity = Severity.high
    ports = [8080, 8081, 80, 443]

    async def check(self, context, host):
        for port in _open(host, set(self.ports)):
            got = await _http_get(context, host.ip, port, "/api/json")
            if got and got[1].status_code == 200 and "jobs" in got[1].text.lower():
                return [_finding(self.id, Severity.high, "Jenkins Anonymous API Access", "Jenkins API is reachable without authentication and exposes job metadata.", f"{got[0]} returned job metadata", "Require authentication, disable anonymous read access, and restrict Jenkins to CI networks.", port)]
        return []

