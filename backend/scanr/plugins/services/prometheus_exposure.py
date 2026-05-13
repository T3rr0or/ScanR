from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class PrometheusExposurePlugin(PluginBase):
    id = "services.prometheus_exposure"
    name = "Prometheus Metrics Exposure"
    description = "Detect exposed Prometheus metrics or UI"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [9090, 9100, 8080, 80, 443]

    async def check(self, context, host):
        for port in _open(host, set(self.ports)):
            for path in ["/metrics", "/targets", "/api/v1/status/config"]:
                got = await _http_get(context, host.ip, port, path)
                if got:
                    url, resp = got
                    text = resp.text[:5000].lower()
                    if resp.status_code == 200 and ("# help" in text or "prometheus" in text or "scrape_configs" in text):
                        return [_finding(self.id, Severity.medium, "Prometheus Data Exposed", "Prometheus metrics/UI may reveal internal hostnames, labels, targets, and service versions.", f"{url} returned Prometheus indicators", "Require authentication or network restrictions for Prometheus and node exporter endpoints.", port)]
        return []

