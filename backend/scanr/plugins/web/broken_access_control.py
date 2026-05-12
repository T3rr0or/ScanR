"""Broken access control detection.

Checks whether admin/management pages return HTTP 200 without any auth
cookies or tokens. A 200 response to an unauthenticated request on a
known admin path strongly suggests missing access control.
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

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]

# Paths that should require authentication
_PROTECTED_PATHS = [
    "/admin", "/admin/", "/admin.php", "/administrator", "/administrator.php",
    "/admindash.php", "/admin_dashboard.php", "/admin/dashboard",
    "/dashboard", "/dashboard.php", "/panel", "/panel.php",
    "/manage", "/manage.php", "/management",
    "/userdash.php", "/user/dashboard", "/account/dashboard",
    "/wp-admin/", "/wp-admin/admin.php",
    "/phpmyadmin/", "/pma/",
    "/api/admin", "/api/v1/admin", "/api/users", "/api/v1/users",
    "/actuator", "/actuator/env", "/actuator/beans", "/actuator/health",
    "/h2-console", "/jmx-console",
    "/console", "/admin/console",
    "/swagger-ui", "/swagger-ui.html", "/api-docs",
    "/config", "/settings", "/server-info",
]

# Keywords indicating a real admin page (not a redirect to login)
# Known paths that are intentionally public by design
_PUBLIC_BY_DESIGN = {
    "/actuator/health", "/actuator/info", "/swagger-ui.html", "/swagger-ui",
    "/api-docs", "/openapi.json", "/docs",
}

# If response contains login-form markers, it's a login page — not broken access control
_LOGIN_INDICATORS = [
    re.compile(r'type=["\']password["\']', re.I),
    re.compile(r'action=["\'][^"\']*(?:login|signin|auth)[^"\']*["\']', re.I),
    re.compile(r'<input[^>]*name=["\'](?:username|email|user)["\']', re.I),
    re.compile(r'(?:please|sign in|log in)\s+(?:to|with)', re.I),
    re.compile(r'access[-_\s]denied|unauthorized|forbidden', re.I),
    re.compile(r'authentication\s+(?:required|needed|failed)', re.I),
]

_ADMIN_CONTENT_SIGNATURES = [
    re.compile(r"dashboard|admin\s+panel|admin\s+dashboard|control\s+panel|management\s+console", re.I),
    re.compile(r"logout|sign\s+out|log\s+out", re.I),
    re.compile(r"welcome.*admin|hello.*admin", re.I),
    re.compile(r"<title>[^<]*(admin|dashboard|panel|manage|control)[^<]*</title>", re.I),
    re.compile(r"user\s+management|role\s+management|system\s+settings", re.I),
]


class BrokenAccessControlPlugin(PluginBase):
    id = "web.broken_access_control"
    name = "Broken Access Control"
    description = "Detect admin/management pages accessible without authentication"
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            port_findings = await self._test(base_url, port.number)
            findings.extend(port_findings)
        return findings

    async def _test(self, base_url: str, port: int) -> list[FindingData]:
        results = []
        try:
            # No cookies, no auth headers — pure unauthenticated request
            async with httpx.AsyncClient(
                verify=False, timeout=6.0, follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR/0.6)"},
                cookies={},
                **context.proxy_config()
            ) as client:
                for path in _PROTECTED_PATHS:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        if resp.status_code != 200:
                            continue
                        body = resp.text
                        # Skip paths that are intentionally public by design
                        if path.rstrip("/") in _PUBLIC_BY_DESIGN or path.rstrip("/") + "/" in _PUBLIC_BY_DESIGN:
                            continue
                        # If response looks like a login page, skip — it's not broken access control
                        if any(li.search(body) for li in _LOGIN_INDICATORS):
                            continue
                        # Must match admin content signature — avoids false positives on
                        # generic 200 pages that happen to share a path name
                        matched = [s for s in _ADMIN_CONTENT_SIGNATURES if s.search(body)]
                        # Require 2+ signatures to reduce false positives (e.g. pages
                        # with a logout link in nav but no actual admin content)
                        if len(matched) < 2:
                            continue
                        results.append(FindingData(
                            plugin_id=self.id,
                            severity=Severity.high,
                            title=f"Broken Access Control: {path} Accessible Without Auth",
                            description=(
                                f"The path '{path}' at {base_url} returned HTTP 200 with admin content "
                                "without any authentication. An unauthenticated attacker can access "
                                "privileged functionality directly."
                            ),
                            evidence=(
                                f"GET {base_url}{path} → HTTP 200\n"
                                f"Matched signatures: {[s.pattern for s in matched]}\n"
                                f"Response snippet: {body[:400]}"
                            ),
                            remediation=(
                                "Enforce authentication on all admin and management endpoints. "
                                "Apply server-side session/token checks — do not rely on URL obscurity. "
                                "Return HTTP 401 or redirect to login for unauthenticated requests."
                            ),
                            references=[
                                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
                            ],
                            port_number=port,
                            protocol="tcp",
                        ))
                    except Exception:
                        continue
        except Exception as exc:
            logger.debug("Access control test failed for %s: %s", base_url, exc)
        return results
