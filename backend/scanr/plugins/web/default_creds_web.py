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
        import json as _json
        _pj: dict = {}
        if context.scan.profile_json:
            try:
                _pj = _json.loads(context.scan.profile_json) if isinstance(context.scan.profile_json, str) else context.scan.profile_json
            except Exception:
                pass
        if not _pj.get("brute_force", {}).get("enabled", False):
            return []

        findings = []
        cfg = context.get_brute_config()
        cred_wl_id = cfg.get("credential_wordlist_id")

        if cred_wl_id:
            custom_creds = list(context.iter_credential_pairs(cred_wl_id))
        else:
            username_wl_id = cfg.get("username_wordlist_id")
            password_wl_id = cfg.get("password_wordlist_id")
            if username_wl_id and password_wl_id:
                users = list(context.iter_wordlist(username_wl_id))[:50]
                pwds = list(context.iter_wordlist(password_wl_id))[:50]
                custom_creds = [(u, p) for u in users for p in pwds]
            else:
                custom_creds = None  # use DEFAULT_CREDS

        creds_to_try = custom_creds if custom_creds is not None else DEFAULT_CREDS

        for port in host.ports:
            if port.number not in HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            delay_s = cfg.get("delay_ms", 500) / 1000.0
            found = await self._try_default_creds(host.ip, port.number, scheme, creds_to_try, delay_s)
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

    async def _try_default_creds(
        self, ip: str, port: int, scheme: str, creds: list[tuple[str, str]], delay_s: float = 0.5
    ) -> list[tuple]:
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

                for username, password in creds:
                    await asyncio.sleep(delay_s)
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
