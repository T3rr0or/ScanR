from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)
HTTP_PORTS = [80, 443, 8080, 8443, 8000]
DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "CONNECT", "PATCH"]


class HttpMethodsPlugin(PluginBase):
    id = "web.http_methods"
    name = "Dangerous HTTP Methods"
    description = "Detect enabled TRACE, PUT, DELETE methods on web servers"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            url = f"{scheme}://{host.ip}:{port.number}/"

            enabled = await self._probe_methods(context, url)
            if "TRACE" in enabled:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="HTTP TRACE Method Enabled (XST Risk)",
                    description="TRACE method is enabled. This can be used for Cross-Site Tracing (XST) attacks to steal cookies.",
                    evidence=f"TRACE request to {url} returned 200 OK",
                    remediation="Disable the TRACE method in your web server configuration.",
                    references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                    port_number=port.number,
                    protocol="tcp",
                ))
            dangerous = [m for m in enabled if m in ("PUT", "DELETE")]
            if dangerous:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title=f"Dangerous HTTP Methods Enabled: {', '.join(dangerous)}",
                    description="Dangerous HTTP methods allow unauthorized file manipulation.",
                    evidence=f"Methods {dangerous} returned success on {url}",
                    remediation="Disable unused HTTP methods. Only allow GET, POST, HEAD where appropriate.",
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _probe_methods(self, context, url: str) -> list[str]:
        enabled = []
        async with httpx.AsyncClient(verify=False, timeout=5.0, **context.proxy_config()) as client:
            for method in DANGEROUS_METHODS:
                try:
                    resp = await client.request(method, url)
                    if 200 <= resp.status_code < 400:
                        enabled.append(method)
                except Exception:
                    pass
        return enabled
