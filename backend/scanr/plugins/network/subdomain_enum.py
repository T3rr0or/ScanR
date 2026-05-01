"""Subdomain enumeration via DNS brute-force + takeover detection.

Resolves common subdomain prefixes against the target's hostname.
After resolving, follows CNAME chains to detect dangling cloud-service
pointers (GitHub Pages, Heroku, Azure, Netlify, etc.) that could be taken over.

Only runs when the host has a resolvable hostname (not bare IP).
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx", "ns1", "ns2",
    "vpn", "remote", "dev", "staging", "test", "demo", "admin", "portal", "api",
    "app", "apps", "mobile", "beta", "alpha", "preview", "old", "new", "secure",
    "shop", "store", "blog", "cms", "cdn", "static", "assets", "media", "img",
    "images", "video", "auth", "login", "sso", "oauth", "id", "account",
    "accounts", "dashboard", "panel", "manage", "management", "control",
    "cpanel", "whm", "plesk", "phpmyadmin", "git", "gitlab", "github", "svn",
    "jenkins", "ci", "build", "deploy", "monitor", "grafana", "kibana",
    "elastic", "search", "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "files", "upload", "uploads", "download", "downloads",
    "internal", "intranet", "corp", "corporate", "help", "support", "ticket",
    "jira", "confluence", "wiki", "docs", "documentation", "status",
    "health", "metrics", "analytics", "track", "tracking",
    "payment", "pay", "billing", "invoice", "checkout",
    "stage", "uat", "qa", "prod", "production", "sandbox",
    "aws", "cloud", "k8s", "kubernetes", "docker", "registry",
    "smtp1", "smtp2", "relay", "gateway", "proxy", "lb", "loadbalancer",
    "fw", "firewall", "router", "switch", "wifi",
]

_MAX_CONCURRENT = 30
_DNS_TIMEOUT = 3.0

# Dangling CNAME patterns → (regex, provider, not-found body substring)
_TAKEOVER_PATTERNS = [
    (re.compile(r'\.github\.io$', re.I),       "GitHub Pages",    "There isn't a GitHub Pages site here"),
    (re.compile(r'\.herokudns\.com$', re.I),   "Heroku",          "No such app"),
    (re.compile(r'\.azurewebsites\.net$', re.I),"Azure App Service","404 Web Site not found"),
    (re.compile(r'\.netlify\.app$', re.I),     "Netlify",         "Not found"),
    (re.compile(r'\.fastly\.net$', re.I),      "Fastly",          "Fastly error"),
    (re.compile(r'\.cloudfront\.net$', re.I),  "AWS CloudFront",  "Bad request"),
    (re.compile(r'\.s3\.amazonaws\.com$', re.I),"AWS S3",          "NoSuchBucket"),
    (re.compile(r'\.surge\.sh$', re.I),        "Surge.sh",        "project not found"),
    (re.compile(r'\.fly\.dev$', re.I),         "Fly.io",          "404"),
    (re.compile(r'\.vercel\.app$', re.I),      "Vercel",          "The deployment could not be found"),
    (re.compile(r'\.pages\.dev$', re.I),       "Cloudflare Pages","not found"),
]


class SubdomainEnumPlugin(PluginBase):
    id = "network.subdomain_enum"
    name = "Subdomain Enumeration"
    description = "Brute-force DNS subdomains for the target hostname"
    category = PluginCategory.network
    severity = Severity.info
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        hostname = host.hostname
        if not hostname or _is_ip(hostname):
            return []

        # Strip leading wildcard prefix to get base domain
        base = hostname.removeprefix("*.")
        if base.count(".") != 1:
            return []

        found = await self._brute_force(base)
        findings = []

        if found:
            lines = "\n".join(f"  {sub} → {ip}" for sub, ip in sorted(found))
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.info,
                title=f"Subdomains Discovered: {len(found)} found for {base}",
                description=(
                    f"{len(found)} subdomains resolved for {base}. "
                    "Additional attack surface may exist on these hosts."
                ),
                evidence=f"Discovered subdomains:\n{lines}",
                remediation=(
                    "Review each discovered subdomain to ensure it is intentional and secured. "
                    "Remove unused or forgotten subdomains. Ensure internal services are not "
                    "inadvertently exposed via DNS."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                ],
                port_number=None,
                protocol="tcp",
            ))

            # Check each discovered subdomain for takeover potential
            takeovers = await self._check_takeovers([sub for sub, _ in found])
            findings.extend(takeovers)

        return findings

    async def _brute_force(self, base_domain: str) -> list[tuple[str, str]]:
        sem = asyncio.Semaphore(_MAX_CONCURRENT)
        loop = asyncio.get_running_loop()

        async def resolve(prefix: str) -> tuple[str, str] | None:
            fqdn = f"{prefix}.{base_domain}"
            async with sem:
                try:
                    ip = await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, fqdn),
                        timeout=_DNS_TIMEOUT,
                    )
                    return (fqdn, ip)
                except Exception:
                    return None

        raw = await asyncio.gather(*[resolve(p) for p in _WORDLIST])
        return [r for r in raw if r is not None]


    async def _check_takeovers(self, subdomains: list[str]) -> list[FindingData]:
        """Follow CNAME chains and check for dangling cloud service pointers."""
        import httpx
        findings = []
        sem = asyncio.Semaphore(10)
        loop = asyncio.get_running_loop()

        async def check_one(fqdn: str) -> FindingData | None:
            async with sem:
                try:
                    # Resolve CNAME chain
                    cname = await asyncio.wait_for(
                        loop.run_in_executor(None, _follow_cname, fqdn),
                        timeout=_DNS_TIMEOUT,
                    )
                    if not cname:
                        return None
                    for pattern, provider, not_found_body in _TAKEOVER_PATTERNS:
                        if pattern.search(cname):
                            # Probe HTTP to confirm not-found response
                            try:
                                async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                                    resp = await client.get(f"http://{fqdn}/")
                                    if not_found_body.lower() in resp.text.lower() or resp.status_code in (404, 410):
                                        return FindingData(
                                            plugin_id="network.subdomain_takeover",
                                            severity=Severity.high,
                                            title=f"Subdomain Takeover: {fqdn} → {provider}",
                                            description=(
                                                f"The subdomain {fqdn} has a CNAME pointing to {cname} ({provider}), "
                                                "but the target resource no longer exists. "
                                                "An attacker can register a matching account/project on {provider} "
                                                "and serve malicious content under the victim's subdomain."
                                            ),
                                            evidence=(
                                                f"FQDN: {fqdn}\n"
                                                f"CNAME target: {cname}\n"
                                                f"Provider: {provider}\n"
                                                f"HTTP {resp.status_code}: {not_found_body!r} found in response"
                                            ),
                                            remediation=(
                                                f"Remove the DNS CNAME record for {fqdn} or reclaim the "
                                                f"{provider} resource at {cname}. "
                                                "Regularly audit DNS records for deprovisioned cloud resources."
                                            ),
                                            references=[
                                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                                                "https://github.com/EdOverflow/can-i-take-over-xyz",
                                            ],
                                            protocol="tcp",
                                        )
                            except Exception:
                                pass
                except Exception:
                    pass
            return None

        results = await asyncio.gather(*[check_one(sub) for sub in subdomains], return_exceptions=True)
        for r in results:
            if isinstance(r, FindingData):
                findings.append(r)
        return findings


_FQDN_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', re.I)


def _follow_cname(fqdn: str) -> str | None:
    """Return the terminal CNAME target, or None if not a CNAME or invalid."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(fqdn, "CNAME")
        cname = str(answers[0].target).rstrip(".")
        # Validate response is a valid hostname before using in regex matching
        if not _FQDN_RE.match(cname) or len(cname) > 253:
            return None
        return cname
    except Exception:
        pass
    return None


def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        return False
