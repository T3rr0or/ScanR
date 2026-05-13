"""SSRF detection.

Tests common URL/target parameters with internal addresses and checks
whether the server makes outbound requests or leaks internal responses.
"""
from __future__ import annotations

import asyncio
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

_SSRF_PARAMS = [
    "url", "uri", "target", "dest", "destination", "redirect", "return",
    "next", "src", "source", "host", "endpoint", "proxy",
    "link", "ref", "fetch", "load", "request", "site", "domain",
    "ssrf", "feed", "webhook", "callback",
]

_FALLBACK_PATHS = [
    "/", "/proxy", "/proxy.php", "/fetch", "/fetch.php",
    "/load", "/load.php", "/request", "/api/fetch",
    "/api/proxy", "/api/load", "/api/v1/fetch",
    "/webhook", "/preview", "/screenshot", "/export",
    "/admin.php", "/dashboard.php", "/admin", "/panel.php",
]

_INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
]

# High-confidence signatures only — no generic HTML match
_INTERNAL_SIGNATURES = [
    re.compile(r"ami-id|instance-id|instance-type|local-ipv4", re.I),
    re.compile(r"computeMetadata|serviceAccounts", re.I),
    re.compile(r"root:x:0:0"),
]

# Multi-param combos where one key is the URL and another is a flag
_SSRF_FLAG_COMBOS: list[tuple[str, str]] = [
    # (url_key, flag_key) — flag_key may be "" if no flag needed
    ("url", "follow"),
    ("target", "fetch"),
    ("src", "load"),
    ("url", ""),
    ("target", ""),
]

_INTERNAL_URL = "http://127.0.0.1/"
_BENIGN_URL = "http://scanr-ssrf-probe.invalid/"


class SsrfDetectPlugin(PluginBase):
    id = "web.ssrf_detect"
    name = "SSRF Detection"
    description = "Detect server-side request forgery via URL/target parameters"
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS
    timeout = 180

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._test_ssrf(context, base_url, port.number)
            if result:
                findings.append(result)
        return findings

    async def _test_ssrf(self, context, base_url: str, port: int) -> FindingData | None:
        sem = asyncio.Semaphore(10)
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=httpx.Timeout(4.0, connect=2.0), follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR/0.6)"},
                **context.proxy_config()
            ) as client:
                crawled = await crawl(base_url, client)
                paths = list(dict.fromkeys(
                    crawled.paths + crawled.form_paths + _FALLBACK_PATHS
                ))[:8]
                params = list(dict.fromkeys(crawled.get_params + _SSRF_PARAMS))[:12]

                # Single-param: inject internal target, check for high-confidence signatures
                async def probe_single(path: str, param: str, target: str) -> FindingData | None:
                    url = f"{base_url}{path}?{param}={target}"
                    async with sem:
                        try:
                            resp = await client.get(url)
                            hit = self._check_signatures(resp)
                            if hit:
                                return self._finding(base_url, port, url, hit, resp)
                        except Exception:
                            pass
                    return None

                tasks = [
                    probe_single(path, param, target)
                    for path in paths
                    for param in params
                    for target in _INTERNAL_TARGETS
                ]
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    if result:
                        return result

                # Multi-param combos: compare response length vs benign baseline
                # Replace only the URL-valued key to keep other params identical
                for path in paths:
                    for url_key, flag_key in _SSRF_FLAG_COMBOS:
                        combo = {url_key: _INTERNAL_URL}
                        benign = {url_key: _BENIGN_URL}
                        if flag_key:
                            combo[flag_key] = "1"
                            benign[flag_key] = "1"
                        try:
                            async with sem:
                                r_benign = await client.get(f"{base_url}{path}", params=benign)
                                r_ssrf = await client.get(f"{base_url}{path}", params=combo)
                            # Signature check first (most reliable)
                            hit = self._check_signatures(r_ssrf)
                            if hit:
                                return self._finding(base_url, port, str(r_ssrf.url), hit, r_ssrf)
                            # Length delta: only flag if both responses are non-trivial
                            # and differ by >20% — avoids firing on dynamic pages
                            b_len = len(r_benign.text)
                            s_len = len(r_ssrf.text)
                            if b_len > 50 and s_len > 50 and abs(s_len - b_len) / max(b_len, 1) > 0.2:
                                hit = "Response length changed significantly when internal target supplied — server likely fetched URL"
                                return self._finding(base_url, port, str(r_ssrf.url), hit, r_ssrf)
                        except Exception:
                            continue
        except Exception as exc:
            logger.debug("SSRF test failed for %s: %s", base_url, exc)
        return None

    def _check_signatures(self, resp: httpx.Response) -> str | None:
        if resp.status_code not in (200, 201):
            return None
        for sig in _INTERNAL_SIGNATURES:
            if sig.search(resp.text):
                return f"Response matches SSRF signature: {sig.pattern}"
        return None

    def _finding(self, base_url: str, port: int, url: str, reason: str, resp: httpx.Response) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="SSRF Detected",
            description=(
                f"The server at {base_url} made an internal HTTP request when supplied with a "
                "URL-type parameter pointing to an internal address. An attacker can use this "
                "to probe internal services, cloud metadata endpoints, or bypass firewall controls."
            ),
            evidence=f"URL: {url}\nReason: {reason}\nResponse snippet: {resp.text[:500]}",
            remediation=(
                "Validate and whitelist allowed URL schemes and destinations for any server-side fetch. "
                "Block requests to RFC1918, loopback, and cloud metadata addresses. "
                "Use an egress firewall to prevent unexpected outbound connections from the application."
            ),
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            ],
            port_number=port,
            protocol="tcp",
        )
