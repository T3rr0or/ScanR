from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class DockerRegistryExposurePlugin(PluginBase):
    id = "services.docker_registry_exposure"
    name = "Docker Registry Exposure"
    description = "Detect unauthenticated Docker Registry catalog access"
    category = PluginCategory.services
    severity = Severity.high
    ports = [5000, 5001, 443, 80]

    async def check(self, context, host):
        for port in _open(host, set(self.ports)):
            got = await _http_get(context, host.ip, port, "/v2/_catalog")
            if got and got[1].status_code == 200 and "repositories" in got[1].text:
                return [_finding(self.id, Severity.high, "Docker Registry Catalog Exposed", "Docker Registry catalog is accessible without authentication, exposing repository names and potentially image layers.", f"{got[0]} returned repositories", "Require registry authentication and restrict /v2/ access to trusted CI/CD systems.", port)]
        return []

