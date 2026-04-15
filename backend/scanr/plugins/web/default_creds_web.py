"""Default web credential checker.

Tests common admin interfaces for default username/password pairs.
Only runs GET/POST against known admin paths — no exploitation.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)
HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888]

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", ""),
    ("administrator", "administrator"),
    ("guest", "guest"),
    ("test", "test"),
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/login", "/wp-login.php",
    "/administrator", "/phpmyadmin", "/pma",
    "/manager/html",  # Tomcat
]


class DefaultCredsWebPlugin(PluginBase):
    id = "web.default_creds_web"
    name = "Default Web Credentials"
    description = "Test for default admin credentials on common web interfaces"
    category = PluginCategory.web
    severity = Severity.critical
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            found = await self._try_default_creds(host.ip, port.number, scheme)
            for username, password, path in found:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title=f"Default Credentials Working: {username}:{password}",
                    description=f"Default credentials were accepted at {path}. An attacker can gain administrative access.",
                    evidence=f"Successful login at {scheme}://{host.ip}:{port.number}{path} with {username}:{password}",
                    remediation="Change all default credentials immediately. Implement account lockout after failed attempts.",
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _try_default_creds(self, ip: str, port: int, scheme: str) -> list[tuple]:
        found = []
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
            for path in ADMIN_PATHS:
                url = f"{scheme}://{ip}:{port}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code not in (200, 401, 403):
                        continue
                except Exception:
                    continue

                for username, password in DEFAULT_CREDS:
                    try:
                        resp = await client.post(
                            url,
                            data={"username": username, "password": password,
                                  "user": username, "pass": password},
                            auth=(username, password),
                            timeout=4.0,
                        )
                        if resp.status_code in (200, 302) and "logout" in resp.text.lower():
                            found.append((username, password, path))
                            break
                    except Exception:
                        continue
        return found
