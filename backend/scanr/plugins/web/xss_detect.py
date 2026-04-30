"""Reflected XSS detection.

Crawls the target to discover real paths and parameters, then injects
payloads and checks if they appear unescaped in the response.
Only tests reflected XSS — no stored/DOM.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme
from scanr.plugins.web._crawler import crawl

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
]

# Generic fallback params (used when crawler finds none)
_FALLBACK_PARAMS = [
    "q", "search", "query", "s", "id", "name", "input", "text",
    "msg", "message", "comment", "title", "page", "cat", "ref",
    "url", "next", "return", "redirect", "keyword", "term",
]

# Generic paths probed in addition to crawled ones — no app-specific entries
_FALLBACK_PATHS = [
    "/search", "/search.php", "/index.php",
    "/admin.php", "/admin", "/dashboard.php", "/panel.php",
    "/profile.php", "/user.php", "/view.php", "/page.php",
    "/news.php", "/article.php", "/product.php", "/item.php",
    "/results.php", "/filter.php", "/list.php",
]

_REFLECTED_RE = re.compile(
    r'(<script[^>]*>.*?alert|onerror\s*=\s*alert)',
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
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._test_xss(base_url, port.number)
            if result:
                findings.append(result)
        return findings

    async def _test_xss(self, base_url: str, port: int) -> FindingData | None:
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=httpx.Timeout(4.0, connect=2.0), follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR/0.6)"},
            ) as client:
                crawled = await crawl(base_url, client)

                # Paths: crawled + form action paths + generic fallbacks
                paths = list(dict.fromkeys(crawled.paths + crawled.form_paths + _FALLBACK_PATHS))
                # Params: crawled GET params + form fields + fallback
                params = list(dict.fromkeys(
                    crawled.get_params + crawled.form_fields + _FALLBACK_PARAMS
                ))

                for path in paths:
                    for param in params:
                        for payload in _PAYLOADS:
                            url = f"{base_url}{path}?{param}={payload}"
                            try:
                                resp = await client.get(url)
                                ct = resp.headers.get("content-type", "")
                                if "text/html" not in ct:
                                    continue
                                # Find payload in response, then check regex only in a window
                                # around it — prevents FP when regex matches unrelated script tag
                                idx = resp.text.find(payload)
                                if idx != -1:
                                    window = resp.text[max(0, idx - 20): idx + len(payload) + 20]
                                else:
                                    window = ""
                                if window and _REFLECTED_RE.search(window):
                                    return FindingData(
                                        plugin_id=self.id,
                                        severity=Severity.high,
                                        title="Reflected XSS Detected",
                                        description=(
                                            f"Parameter '{param}' at {base_url}{path} reflects unsanitised "
                                            "input back into the HTML response, enabling reflected XSS."
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
