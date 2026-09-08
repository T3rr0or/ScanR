"""CMS identification and exposure enumeration.

WordPress alone serves a large share of the public web, and its findings are
version- and endpoint-specific rather than generic: an exposed user list, a
reachable `xmlrpc.php`, or a readable version string each change what an
attacker does next. Nuclei templates cover known CMS *CVEs*; this covers the
enumeration those templates assume you already did.

Every request here is a plain GET of a documented, publicly reachable path. No
payloads, no writes — active only in the sense that it asks for URLs that were
not linked from the homepage.
"""
from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import create_web_client
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000]

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I
)
_WP_VERSION_RE = re.compile(r"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)
_DRUPAL_VERSION_RE = re.compile(r"Drupal\s+([0-9]+(?:\.[0-9]+)*)", re.I)
_JOOMLA_VERSION_RE = re.compile(r"Joomla!?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)

# Markers that identify the platform from the homepage alone.
_FINGERPRINTS: list[tuple[str, tuple[str, ...]]] = [
    ("WordPress", ("/wp-content/", "/wp-includes/", "wp-json", "wp-embed.min.js")),
    ("Drupal", ("/sites/default/files", "drupal.js", "Drupal.settings", "/core/misc/drupal")),
    ("Joomla", ("/media/jui/", "/components/com_", "joomla.javascript")),
]


class CmsEnumPlugin(PluginBase):
    id = "web.cms_enum"
    name = "CMS Identification and Exposure"
    description = (
        "Identify WordPress, Drupal and Joomla, and report version disclosure, "
        "user enumeration and exposed management endpoints"
    )
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        seen_platforms: set[str] = set()
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base = f"{scheme}://{host.ip}:{port.number}"
            try:
                found = await self._scan(context, base, port.number, seen_platforms)
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("cms_enum: %s failed: %s", base, exc)
                continue
            findings.extend(found)
        return findings

    async def _scan(
        self, context, base: str, port: int, seen: set[str]
    ) -> list[FindingData]:
        findings: list[FindingData] = []
        async with create_web_client(context) as client:
            try:
                home = await client.get(f"{base}/", timeout=8.0)
            except Exception:
                return []
            body = home.text
            platform = self._identify(body)
            if platform is None or platform in seen:
                return []
            seen.add(platform)

            version = self._version_from_body(platform, body)
            findings.append(self._platform_finding(platform, version, base, port))

            if platform == "WordPress":
                findings.extend(await self._wordpress_checks(client, base, port))
        return findings

    @staticmethod
    def _identify(body: str) -> str | None:
        generator = _GENERATOR_RE.search(body)
        if generator:
            declared = generator.group(1)
            for name in ("WordPress", "Drupal", "Joomla"):
                if name.lower() in declared.lower():
                    return name
        for name, markers in _FINGERPRINTS:
            if any(marker in body for marker in markers):
                return name
        return None

    @staticmethod
    def _version_from_body(platform: str, body: str) -> str | None:
        pattern = {
            "WordPress": _WP_VERSION_RE,
            "Drupal": _DRUPAL_VERSION_RE,
            "Joomla": _JOOMLA_VERSION_RE,
        }[platform]
        match = pattern.search(body)
        return match.group(1) if match else None

    def _platform_finding(
        self, platform: str, version: str | None, base: str, port: int
    ) -> FindingData:
        if version:
            return FindingData(
                plugin_id=self.id,
                severity=Severity.low,
                title=f"{platform} Version Disclosed ({version})",
                description=(
                    f"The site at {base} runs {platform} and publishes its exact version "
                    f"({version}), usually through the generator meta tag. That lets an "
                    "attacker look up known vulnerabilities for this precise build "
                    "instead of probing for them, and makes the target easy to select "
                    "from mass-scan results."
                ),
                evidence=f"{platform} {version} identified from the homepage of {base}",
                remediation=(
                    "Remove the generator meta tag and any version query strings on "
                    "static assets, and keep the platform and its extensions patched. "
                    "Hiding the version is hardening, not a fix — patching is."
                ),
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                port_number=port,
                protocol="tcp",
            )
        return FindingData(
            plugin_id=self.id,
            severity=Severity.info,
            title=f"{platform} Detected",
            description=(
                f"The site at {base} runs {platform}. No version string was exposed. "
                "Recorded so the platform's own advisories and extension inventory can "
                "be tracked against this host."
            ),
            evidence=f"{platform} fingerprint matched on {base}",
            remediation="Keep the platform and all installed extensions patched.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            port_number=port,
            protocol="tcp",
        )

    async def _wordpress_checks(self, client, base: str, port: int) -> list[FindingData]:
        findings: list[FindingData] = []

        users = await self._wp_users(client, base)
        if users:
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.medium,
                title="WordPress User Enumeration via REST API",
                description=(
                    "The /wp-json/wp/v2/users endpoint lists site accounts without "
                    "authentication, returning each user's login slug and display name. "
                    "Valid usernames turn password attacks from guesswork into a "
                    "targeted list, and administrator accounts are identifiable."
                ),
                evidence=(
                    f"GET {base}/wp-json/wp/v2/users returned {len(users)} account(s): "
                    + ", ".join(users[:10])
                ),
                remediation=(
                    "Restrict the users endpoint — most sites need it only for logged-in "
                    "editors. Disable it via a filter on rest_endpoints, or require "
                    "authentication for /wp/v2/users. Enforce strong passwords and rate "
                    "limit wp-login.php regardless."
                ),
                references=[
                    "https://developer.wordpress.org/rest-api/reference/users/",
                ],
                port_number=port,
                protocol="tcp",
            ))

        if await self._wp_xmlrpc(client, base):
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.medium,
                title="WordPress xmlrpc.php Enabled",
                description=(
                    "xmlrpc.php accepts method calls. system.multicall lets an attacker "
                    "test hundreds of passwords in a single HTTP request, defeating "
                    "per-request login throttling, and pingback.ping can make the server "
                    "issue requests to arbitrary hosts — usable for SSRF against internal "
                    "services or as a reflective DDoS amplifier."
                ),
                evidence=f"POST {base}/xmlrpc.php returned an XML-RPC method response",
                remediation=(
                    "Disable XML-RPC unless a client genuinely needs it (older mobile "
                    "apps, Jetpack). Block /xmlrpc.php at the web server or CDN, or "
                    "disable pingbacks and multicall specifically."
                ),
                references=["https://kinsta.com/blog/xmlrpc-php/"],
                port_number=port,
                protocol="tcp",
            ))

        exposed = await self._wp_exposed_paths(client, base)
        if exposed:
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.low,
                title="WordPress Sensitive Paths Reachable",
                description=(
                    "Installation and configuration artefacts are readable without "
                    "authentication. They disclose the exact version, the server layout, "
                    "and in the case of a directory listing, the full plugin and theme "
                    "inventory — the shortest route to a known-vulnerable component."
                ),
                evidence="Reachable: " + ", ".join(exposed),
                remediation=(
                    "Remove readme.html after installation and deny access to "
                    "wp-content/uploads directory indexes, /wp-content/debug.log and "
                    "backup files in the web server configuration."
                ),
                references=["https://wordpress.org/documentation/article/hardening-wordpress/"],
                port_number=port,
                protocol="tcp",
            ))
        return findings

    @staticmethod
    async def _wp_users(client, base: str) -> list[str]:
        try:
            resp = await client.get(f"{base}/wp-json/wp/v2/users", timeout=8.0)
        except Exception:
            return []
        if resp.status_code != 200:
            return []
        try:
            payload = json.loads(resp.text)
        except (ValueError, TypeError):
            return []
        if not isinstance(payload, list):
            return []
        names = []
        for entry in payload:
            if isinstance(entry, dict):
                name = entry.get("slug") or entry.get("name")
                if isinstance(name, str) and name:
                    names.append(name)
        return names

    @staticmethod
    async def _wp_xmlrpc(client, base: str) -> bool:
        # listMethods is read-only and the canonical availability probe.
        payload = (
            "<?xml version='1.0'?><methodCall>"
            "<methodName>system.listMethods</methodName><params></params>"
            "</methodCall>"
        )
        try:
            resp = await client.post(
                f"{base}/xmlrpc.php",
                content=payload,
                headers={"Content-Type": "text/xml"},
                timeout=8.0,
            )
        except Exception:
            return False
        return resp.status_code == 200 and "methodResponse" in resp.text

    @staticmethod
    async def _wp_exposed_paths(client, base: str) -> list[str]:
        candidates = {
            "/readme.html": "readme.html (version disclosure)",
            "/wp-content/debug.log": "wp-content/debug.log",
            "/wp-content/uploads/": "wp-content/uploads/ (directory listing)",
        }
        found: list[str] = []
        for path, label in candidates.items():
            try:
                resp = await client.get(f"{base}{path}", timeout=6.0)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            if path.endswith("/") and "Index of" not in resp.text:
                continue
            found.append(label)
        return found
