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

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000]

REQUIRED_HEADERS = {
    "Strict-Transport-Security": (
        Severity.high,
        "HSTS Not Set",
        "Missing HTTP Strict Transport Security header allows downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    ),
    "X-Content-Type-Options": (
        Severity.medium,
        "X-Content-Type-Options Not Set",
        "Missing header allows MIME-type sniffing attacks.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    "X-Frame-Options": (
        Severity.medium,
        "Clickjacking Protection Missing",
        "Missing X-Frame-Options allows the page to be embedded in iframes (clickjacking).",
        "Add: X-Frame-Options: SAMEORIGIN or use CSP frame-ancestors directive.",
    ),
    "Content-Security-Policy": (
        Severity.medium,
        "Content Security Policy Not Set",
        "Missing CSP header increases risk of XSS attacks.",
        "Define a Content-Security-Policy header appropriate for the application.",
    ),
    # X-XSS-Protection intentionally removed — header was deprecated by all major
    # browsers (Chrome 78+, Firefox 3.6+, Edge 2019+). Recommending it is incorrect
    # guidance; certain configurations can even introduce XSS vulnerabilities.
    # Use Content-Security-Policy instead. OWASP Secure Headers Project no longer
    # lists it as a required header (as of 2021).
    "Referrer-Policy": (
        Severity.low,
        "Referrer-Policy Not Set",
        "Missing Referrer-Policy may leak sensitive URL data to third parties.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        Severity.low,
        "Permissions-Policy Not Set",
        "Missing Permissions-Policy header allows unrestricted browser feature access.",
        "Add a Permissions-Policy header to restrict access to browser APIs.",
    ),
}

LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


class HttpHeadersPlugin(PluginBase):
    id = "web.http_headers"
    name = "Missing Security Headers"
    description = "Check for missing HTTP security headers"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            headers = await self._fetch_headers(host.ip, port.number, scheme)
            if headers is None:
                # Try the other scheme
                scheme = "https" if scheme == "http" else "http"
                headers = await self._fetch_headers(host.ip, port.number, scheme)
            if not headers:
                continue

            headers_lower = {k.lower(): v for k, v in headers.items()}

            for header, (sev, title, desc, remediation) in REQUIRED_HEADERS.items():
                if header.lower() not in headers_lower:
                    findings.append(FindingData(
                        plugin_id=self.id,
                        severity=sev,
                        title=title,
                        description=desc,
                        evidence=f"Header '{header}' absent in response from {scheme}://{host.ip}:{port.number}/",
                        remediation=remediation,
                        references=["https://owasp.org/www-project-secure-headers/"],
                        port_number=port.number,
                        protocol="tcp",
                    ))

            # Check for information-leaking headers
            leaking = [h for h in LEAK_HEADERS if h.lower() in headers_lower]
            if leaking:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.info,
                    title="Server Information Disclosed in Headers",
                    description="Response headers reveal server software and version information.",
                    evidence=", ".join(f"{h}: {headers_lower[h.lower()]}" for h in leaking),
                    remediation="Remove or sanitize Server, X-Powered-By, and version headers.",
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _fetch_headers(self, ip: str, port: int, scheme: str) -> dict | None:
        url = f"{scheme}://{ip}:{port}/"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
                resp = await client.get(url)
                return dict(resp.headers)
        except Exception:
            return None
