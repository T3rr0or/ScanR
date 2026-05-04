from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlparse

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

REDIRECT_PARAMS = ["url", "next", "redirect", "return", "returnUrl", "return_url",
                   "redirect_uri", "redirectUrl", "goto", "target", "dest", "destination"]
CANARY = "https://evil.example.com"


class OpenRedirectPlugin(PluginBase):
    id = "web.open_redirect"
    name = "Open Redirect"
    description = "Test for open redirect vulnerabilities via common redirect parameters"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            finding = await self._test_redirects(host.ip, port.number, scheme)
            if not finding and scheme == "http":
                finding = await self._test_redirects(host.ip, port.number, "https")
            if finding:
                findings.append(finding)
        return findings

    async def _test_redirects(self, ip: str, port: int, scheme: str) -> FindingData | None:
        base = f"{scheme}://{ip}:{port}/"
        try:
            async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(3.0, connect=2.0), follow_redirects=False) as client:
                for param in REDIRECT_PARAMS:
                    url = base + "?" + urlencode({param: CANARY})
                    try:
                        resp = await client.get(url)
                        location = resp.headers.get("location", "")
                        # Only flag if redirect goes TO external host, not just contains it as query param
                        if location:
                            parsed = urlparse(location)
                            if parsed.hostname and "evil.example.com" in parsed.hostname:
                                pass  # true open redirect — will fall through to return
                            elif "evil.example.com" in parsed.query or "evil.example.com" in parsed.path:
                                # Canary appears in redirect query/path but host is internal — likely login redirect
                                if resp.status_code in (301, 302, 307, 308) and parsed.hostname is None:
                                    # Relative redirect to same origin with canary in params — skip
                                    continue
                            else:
                                continue  # no canary in location at all
                        else:
                            continue
                            return FindingData(
                                plugin_id=self.id,
                                severity=Severity.medium,
                                title="Open Redirect",
                                description=(
                                    "The application redirects to an attacker-controlled URL via the "
                                    f"'{param}' parameter. This can be used for phishing attacks."
                                ),
                                evidence=f"GET {url} → Location: {location}",
                                remediation=(
                                    "Validate redirect targets against an allowlist of trusted domains. "
                                    "Reject or sanitize external URLs."
                                ),
                                references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                                port_number=port,
                                protocol="tcp",
                            )
                    except Exception:
                        continue
        except Exception:
            pass
        return None
