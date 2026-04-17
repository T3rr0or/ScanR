"""Reflected XSS detection.

Injects payloads into URL parameters and checks if the payload appears
unescaped in the response body. Only tests reflected XSS — no stored/DOM.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]

_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]

_TEST_PARAMS = ["q", "search", "query", "s", "name", "input", "text", "msg", "message", "comment", "title", "page"]

_REFLECTED_RE = re.compile(
    r'(<script[^>]*>.*?alert|onerror\s*=\s*alert|javascript\s*:\s*alert)',
    re.IGNORECASE | re.DOTALL,
)


class XssDetectPlugin(PluginBase):
    id = "web.xss_detect"
    name = "Reflected XSS"
    description = "Detect reflected cross-site scripting in URL parameters"
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._test_xss(base_url, port.number)
            if result:
                findings.append(result)
        return findings

    async def _test_xss(self, base_url: str, port: int) -> FindingData | None:
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=8.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR/0.6)"},
            ) as client:
                for param in _TEST_PARAMS:
                    for payload in _PAYLOADS:
                        url = f"{base_url}/?{param}={payload}"
                        try:
                            resp = await client.get(url)
                            content_type = resp.headers.get("content-type", "")
                            if "text/html" not in content_type:
                                continue
                            if payload in resp.text and _REFLECTED_RE.search(resp.text):
                                return FindingData(
                                    plugin_id=self.id,
                                    severity=Severity.high,
                                    title="Reflected XSS Detected",
                                    description=(
                                        f"Parameter '{param}' at {base_url} reflects unsanitised input "
                                        "back into the HTML response, enabling reflected cross-site scripting."
                                    ),
                                    evidence=f"URL: {url}\nPayload reflected unescaped in response.\nSnippet: {resp.text[:500]}",
                                    remediation=(
                                        "HTML-encode all user-supplied input before reflecting it in responses. "
                                        "Use a Content Security Policy to restrict script execution. "
                                        "Never insert untrusted data into HTML without escaping."
                                    ),
                                    references=[
                                        "https://owasp.org/www-community/attacks/xss/",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                    ],
                                    port_number=port,
                                    protocol="tcp",
                                )
                        except Exception:
                            continue
        except Exception as exc:
            logger.debug("XSS test failed for %s: %s", base_url, exc)
        return None
