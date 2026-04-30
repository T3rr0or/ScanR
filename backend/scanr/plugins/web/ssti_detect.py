"""Server-Side Template Injection (SSTI) detection.

Uses math-evaluation fingerprinting: injects {{7*7}}, #set($x=7*7)${x}, ${7*7} etc.
and checks whether '49' appears in the response where it did not in a baseline.

No intrusive gate needed — math expressions are non-destructive.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme
from scanr.plugins.web._crawler import crawl
from scanr.plugins.web._http_evidence import format_from_httpx

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]

# (engine_name, payload, expected_output)
_PAYLOADS = [
    ("Jinja2/Twig",   "{{7*7}}",                 "49"),
    ("Jinja2",        "{{7*'7'}}",                "7777777"),   # distinguishes from Twig
    ("FreeMarker",    "${7*7}",                   "49"),
    ("Mako",          "${7*7}",                   "49"),
    ("Velocity",      "#set($x=7*7)${x}",         "49"),
    ("Smarty",        "{7*7}",                    "49"),
    ("ERB",           "<%= 7 * 7 %>",             "49"),
    ("Pebble",        "{{7*7}}",                  "49"),
    ("Handlebars",    "{{#with 7 as |n|}}{{n}}{{/with}}", "7"),
]

_TEST_PARAMS = ["q", "search", "name", "template", "msg", "message", "text", "content", "subject", "title", "query"]
_BASELINE_VALUE = "ssti_baseline_xyz_12345"


class SstiDetectPlugin(PluginBase):
    id = "web.ssti_detect"
    name = "Server-Side Template Injection (SSTI)"
    description = "Detect SSTI via math-evaluation fingerprinting across Jinja2, FreeMarker, Velocity, Mako, Smarty, and ERB"
    category = PluginCategory.web
    severity = Severity.critical
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._test_ssti(base_url, port.number, host.ip)
            if result:
                findings.append(result)
        return findings

    async def _test_ssti(self, base_url: str, port: int, ip: str) -> FindingData | None:
        sem = asyncio.Semaphore(10)
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=httpx.Timeout(4.0, connect=2.0), follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR/0.6)"},
            ) as client:
                crawled = await crawl(base_url, client)
                params = list(dict.fromkeys(crawled.get_params + _TEST_PARAMS))
                paths = crawled.paths or ["/"]

                for path in paths[:5]:
                    for param in params[:8]:
                        # Get baseline — must not contain our expected math outputs
                        try:
                            baseline = await client.get(f"{base_url}{path}?{param}={_BASELINE_VALUE}")
                            baseline_text = baseline.text
                        except Exception:
                            continue

                        for engine, payload, expected in _PAYLOADS:
                            async with sem:
                                try:
                                    resp = await client.get(f"{base_url}{path}?{param}={payload}")
                                    if expected in resp.text and expected not in baseline_text:
                                        return FindingData(
                                            plugin_id=self.id,
                                            severity=Severity.critical,
                                            title=f"Server-Side Template Injection (SSTI) — {engine}",
                                            description=(
                                                f"Parameter '{param}' at {base_url}{path} evaluates template expressions. "
                                                f"The {engine} payload {payload!r} produced output {expected!r} in the response. "
                                                "An attacker can use SSTI to read server files, execute OS commands, "
                                                "or achieve remote code execution."
                                            ),
                                            evidence=(
                                                f"Engine: {engine}\nPayload: {payload!r}\nExpected output: {expected!r}\n\n"
                                                f"{format_from_httpx(resp)}"
                                            ),
                                            remediation=(
                                                "Never pass user input directly to template render functions. "
                                                "Use a sandboxed template environment. "
                                                "Validate and sanitise all user input before use in templates."
                                            ),
                                            references=[
                                                "https://portswigger.net/web-security/server-side-template-injection",
                                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
                                            ],
                                            port_number=port,
                                            protocol="tcp",
                                        )
                                except Exception:
                                    pass

                # Also test common headers
                for engine, payload, expected in _PAYLOADS[:4]:  # top 4 most common
                    for header in ["User-Agent", "Referer", "X-Forwarded-For"]:
                        async with sem:
                            try:
                                resp = await client.get(f"{base_url}/", headers={header: payload})
                                if expected in resp.text:
                                    return FindingData(
                                        plugin_id=self.id,
                                        severity=Severity.critical,
                                        title=f"Server-Side Template Injection (SSTI) via Header — {engine}",
                                        description=(
                                            f"HTTP header {header!r} is rendered through a template engine. "
                                            f"The {engine} payload {payload!r} produced {expected!r}. "
                                            "Remote code execution is achievable."
                                        ),
                                        evidence=f"Engine: {engine}\nHeader: {header}: {payload}\nOutput: {expected}\n\n{format_from_httpx(resp)}",
                                        remediation="Do not render HTTP headers through template engines. Sanitise all user-controlled input.",
                                        references=["https://portswigger.net/web-security/server-side-template-injection"],
                                        port_number=port,
                                        protocol="tcp",
                                    )
                            except Exception:
                                pass
        except Exception as exc:
            logger.debug("SSTI test failed for %s: %s", base_url, exc)
        return None
