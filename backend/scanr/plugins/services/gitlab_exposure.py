from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class GitLabExposurePlugin(PluginBase):
    id = "services.gitlab_exposure"
    name = "GitLab Exposure"
    description = "Detect exposed GitLab instance and public registration hints"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [80, 443, 8080]

    async def check(self, context, host):
        for port in _open(host, set(self.ports)):
            got = await _http_get(context, host.ip, port, "/users/sign_in")
            if got and "gitlab" in got[1].text[:10000].lower():
                reg = "register" in got[1].text[:10000].lower()
                return [_finding(self.id, Severity.medium, "GitLab Instance Exposed", "GitLab is publicly reachable; registration or version hints may increase attack surface.", f"{got[0]} returned GitLab login; registration_hint={reg}", "Restrict GitLab exposure, disable public sign-up unless required, and keep GitLab patched.", port)]
        return []

