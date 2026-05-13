from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class ConsulVaultNomadExposurePlugin(PluginBase):
    id = "services.consul_vault_nomad_exposure"
    name = "Consul / Vault / Nomad Exposure"
    description = "Detect exposed HashiCorp service APIs"
    category = PluginCategory.services
    severity = Severity.high
    ports = [8500, 8200, 4646]

    async def check(self, context, host):
        checks = [(8500, "/v1/status/leader", "Consul"), (8200, "/v1/sys/health", "Vault"), (4646, "/v1/status/leader", "Nomad")]
        for port, path, name in checks:
            if port not in _open(host, {port}):
                continue
            got = await _http_get(context, host.ip, port, path)
            if got and got[1].status_code in {200, 429, 472, 473, 501, 503}:
                return [_finding(self.id, Severity.high, f"{name} API Exposed", f"{name} control-plane API is reachable and may disclose cluster state or permit unauthenticated operations depending on ACL posture.", f"{got[0]} returned HTTP {got[1].status_code}", f"Enable {name} ACLs/TLS and restrict API access to trusted management networks.", port)]
        return []

