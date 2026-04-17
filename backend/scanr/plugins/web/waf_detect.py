"""WAF / CDN detection.

Sends a known malicious payload and inspects response headers and status
codes for WAF fingerprints. Also checks for CDN/proxy headers.
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

# WAF fingerprints: (name, header/body pattern, type)
_WAF_SIGNATURES: list[tuple[str, str, str]] = [
    ("Cloudflare", "cf-ray", "header"),
    ("Cloudflare", "server: cloudflare", "header"),
    ("AWS WAF", "x-amzn-requestid", "header"),
    ("AWS WAF", "x-amz-cf-id", "header"),
    ("Akamai", "akamai-origin-hop", "header"),
    ("Akamai", "x-akamai-transformed", "header"),
    ("Fastly", "x-served-by", "header"),
    ("Fastly", "fastly-restarts", "header"),
    ("Sucuri", "x-sucuri-id", "header"),
    ("Sucuri", "x-sucuri-cache", "header"),
    ("Imperva Incapsula", "x-iinfo", "header"),
    ("Imperva Incapsula", "incap_ses", "header"),
    ("F5 BIG-IP ASM", "x-cnection", "header"),
    ("ModSecurity", "mod_security", "body"),
    ("ModSecurity", "not acceptable", "body_403"),
    ("Barracuda", "barra_counter_session", "header"),
    ("Citrix NetScaler", "ns_af", "header"),
    ("Fortinet FortiWeb", "fortiwafsid", "header"),
    ("Radware AppWall", "x-sl-compstate", "header"),
    ("Cloudfront", "x-cache: hit from cloudfront", "header"),
    ("Cloudfront", "via: cloudfront", "header"),
]

# Probe payload designed to trigger WAF rules
_WAF_PROBE = "/?id=1'+AND+1=1--&q=<script>alert(1)</script>&cmd=cat+/etc/passwd"


class WafDetectPlugin(PluginBase):
    id = "web.waf_detect"
    name = "WAF / CDN Detection"
    description = "Detect web application firewalls and CDN proxies"
    category = PluginCategory.web
    severity = Severity.info
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._detect_waf(base_url, port.number)
            if result:
                findings.append(result)
        return findings

    async def _detect_waf(self, base_url: str, port: int) -> FindingData | None:
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=8.0, follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR/0.6)"},
            ) as client:
                probe_url = f"{base_url}{_WAF_PROBE}"
                try:
                    resp = await client.get(probe_url)
                except Exception:
                    return None

                detected: list[str] = []
                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                body_lower = resp.text[:2000].lower()

                for waf_name, pattern, match_type in _WAF_SIGNATURES:
                    if waf_name in detected:
                        continue
                    if match_type == "header":
                        key, _, val = pattern.partition(": ")
                        if val:
                            if key in headers_lower and val in headers_lower[key]:
                                detected.append(waf_name)
                        else:
                            if key in headers_lower:
                                detected.append(waf_name)
                    elif match_type == "body" and pattern in body_lower:
                        detected.append(waf_name)
                    elif match_type == "body_403" and resp.status_code == 403 and pattern in body_lower:
                        detected.append(waf_name)

                # Generic: 403/406 on probe with no specific match = likely WAF
                if not detected and resp.status_code in (403, 406, 429, 503):
                    detected.append("Unknown WAF")

                if not detected:
                    return None

                waf_str = ", ".join(detected)
                header_dump = "\n".join(f"  {k}: {v}" for k, v in list(resp.headers.items())[:20])

                return FindingData(
                    plugin_id=self.id,
                    severity=Severity.info,
                    title=f"WAF/CDN Detected: {waf_str}",
                    description=(
                        f"A web application firewall or CDN was detected in front of {base_url}. "
                        f"Detected: {waf_str}. WAF presence does not eliminate vulnerabilities but "
                        "may reduce attack surface and requires bypass techniques for further testing."
                    ),
                    evidence=f"Probe URL: {probe_url}\nHTTP {resp.status_code}\nHeaders:\n{header_dump}",
                    remediation=(
                        "WAF detection is informational. Ensure the WAF is kept up to date with current rulesets. "
                        "Do not rely on WAF as the sole protection — fix underlying vulnerabilities."
                    ),
                    references=[
                        "https://owasp.org/www-project-web-application-firewall-evaluation-criteria/",
                    ],
                    port_number=port,
                    protocol="tcp",
                )
        except Exception as exc:
            logger.debug("WAF detection failed for %s: %s", base_url, exc)
        return None
