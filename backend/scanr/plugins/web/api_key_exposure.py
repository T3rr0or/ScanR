"""API Key Exposure detection.

Scans HTML/JS responses for hardcoded API keys and secret tokens
embedded in client-side code.
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

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000]

_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub Token", re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}")),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Public Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,48}")),
    ("Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}")),
    ("SendGrid API Key", re.compile(r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}")),
    ("Generic Secret", re.compile(r'(?i)(?:secret|token|api_key|apikey|api-key)\s*[=:]\s*["\']([^"\']{8,})["\']')),
    ("Bearer Token", re.compile(r'(?i)authorization["\s]*:\s*["\s]*bearer\s+[a-zA-Z0-9._\-]{20,}')),
]


class ApiKeyExposurePlugin(PluginBase):
    id = "web.api_key_exposure"
    name = "API Key Exposure"
    description = "Scan HTML/JS responses for hardcoded API keys and secret tokens"
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
            result = await self._scan_for_keys(context, base_url, port.number)
            if result:
                findings.append(result)
        return findings

    async def _scan_for_keys(self, context, base_url: str, port: int) -> FindingData | None:
        hits: list[dict] = []
        scanned_urls: set[str] = set()

        async with httpx.AsyncClient(
            verify=False,
            timeout=8.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ScanR)"},
        **context.proxy_config(),
            ) as client:
            # Get main page
            try:
                resp = await client.get(f"{base_url}/")
                content = resp.text
                self._scan_content(content, f"{base_url}/", hits)
                scanned_urls.add(f"{base_url}/")

                # Extract JS file URLs
                js_urls = re.findall(
                    r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', content, re.I
                )
            except Exception:
                return None

            # Fetch and scan JS files
            for js_url in js_urls[:10]:
                if not js_url.startswith("http"):
                    js_url = base_url.rstrip("/") + "/" + js_url.lstrip("/")
                if js_url in scanned_urls:
                    continue
                scanned_urls.add(js_url)
                try:
                    r = await client.get(js_url)
                    if r.status_code == 200 and len(r.text) < 500_000:
                        self._scan_content(r.text, js_url, hits)
                except Exception:
                    pass

        if not hits:
            return None

        # Deduplicate by pattern name + masked value
        seen: set[tuple[str, str]] = set()
        unique_hits: list[dict] = []
        for hit in hits:
            key = (hit["pattern"], hit["masked"])
            if key not in seen:
                seen.add(key)
                unique_hits.append(hit)

        evidence_lines = [
            f"[{h['pattern']}] in {h['url']}: {h['masked']}"
            for h in unique_hits[:10]
        ]

        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title=f"Hardcoded API Keys/Secrets Found ({len(unique_hits)} match(es))",
            description=(
                f"Hardcoded API keys or secret tokens were found in publicly accessible HTML/JavaScript "
                f"at {base_url}. These credentials are exposed to any visitor and can be used to "
                "access third-party services, cloud accounts, or internal APIs."
            ),
            evidence="\n".join(evidence_lines),
            remediation=(
                "Remove all hardcoded credentials from client-side code immediately. "
                "Rotate all exposed API keys/tokens. "
                "Use environment variables or a secrets manager for backend credentials. "
                "Scan git history for historical exposure (truffleHog, git-secrets)."
            ),
            references=[
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ],
            port_number=port,
            protocol="tcp",
        )

    _PLACEHOLDERS = frozenset({
        "password", "your_password", "changeme", "xxxxxxxx", "placeholder",
        "example", "test", "secret", "token", "api_key", "apikey", "your_token",
        "your_secret", "your_api_key", "insert_key_here", "replace_me",
    })

    # Matches dotted/snake_case identifiers like "mealie.access_token", "auth_token_key"
    # — these are variable/config names, not actual secret values.
    _IDENTIFIER_RE = re.compile(r'^[a-z][a-z0-9._\-]*$')

    def _has_entropy(self, val: str) -> bool:
        """Reject low-entropy / placeholder values for the Generic Secret pattern."""
        lower = val.lower().strip("'\"")
        if lower in self._PLACEHOLDERS:
            return False
        if len(set(lower)) < 6:  # "aaaaaaaa" style
            return False
        # Reject values that look like identifier/variable names (all lowercase + dots/underscores/dashes).
        # Real secrets contain uppercase letters, digits, or are significantly longer.
        if self._IDENTIFIER_RE.match(lower) and not any(c.isdigit() for c in lower):
            return False
        return True

    def _scan_content(self, content: str, url: str, hits: list) -> None:
        for pattern_name, regex in _PATTERNS:
            for match in regex.finditer(content):
                val = match.group()
                # For Generic Secret, check the captured group (the value) for entropy
                if pattern_name == "Generic Secret":
                    captured = match.group(1) if match.lastindex else val
                    if not self._has_entropy(captured):
                        continue
                masked = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:3] + "..."
                hits.append({"pattern": pattern_name, "url": url, "masked": masked})
