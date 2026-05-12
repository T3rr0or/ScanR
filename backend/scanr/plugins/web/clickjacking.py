"""Clickjacking protection plugin.

Checks for X-Frame-Options header and CSP frame-ancestors directive.
More targeted than the generic http_headers check.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)
HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]


class ClickjackingPlugin(PluginBase):
    id = "web.clickjacking"
    name = "Clickjacking Protection Missing"
    description = "Check for missing X-Frame-Options or CSP frame-ancestors directive"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        checked: set[int] = set()
        for port in host.ports:
            if not is_web_port(port) or port.number in checked:
                continue
            checked.add(port.number)
            scheme = web_scheme(port)
            headers = await self._fetch_headers(host.ip, port.number, scheme)
            if headers is None:
                scheme = "https" if scheme == "http" else "http"
                headers = await self._fetch_headers(host.ip, port.number, scheme)
            if not headers:
                continue

            lower = {k.lower(): v for k, v in headers.items()}
            xfo = lower.get("x-frame-options", "")
            csp = lower.get("content-security-policy", "")
            has_frame_ancestors = "frame-ancestors" in csp.lower()
            has_xfo = bool(xfo)

            if not has_xfo and not has_frame_ancestors:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Clickjacking Protection Missing",
                    description=(
                        "The response lacks both X-Frame-Options and a CSP frame-ancestors directive. "
                        "An attacker can embed this page in an iframe on a malicious site to trick users "
                        "into clicking invisible UI elements (UI redressing / clickjacking)."
                    ),
                    evidence=f"No X-Frame-Options or CSP frame-ancestors on {scheme}://{host.ip}:{port.number}/",
                    remediation=(
                        "Add 'X-Frame-Options: SAMEORIGIN' or a CSP header with "
                        "'frame-ancestors 'self'' directive. Prefer CSP as X-Frame-Options is deprecated."
                    ),
                    references=["https://owasp.org/www-community/attacks/Clickjacking"],
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _fetch_headers(self, ip: str, port: int, scheme: str) -> dict | None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True,
                **context.proxy_config()
            ) as client:
                resp = await client.get(f"{scheme}://{ip}:{port}/")
                return dict(resp.headers)
        except Exception:
            return None
