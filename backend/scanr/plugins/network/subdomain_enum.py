"""Subdomain enumeration via DNS brute-force.

Resolves common subdomain prefixes against the target's hostname.
Only runs when the host has a resolvable hostname (not bare IP).
"""
from __future__ import annotations

import asyncio
import logging
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

        # Strip leading wildcard or www prefix to get base domain
        base = hostname.lstrip("*.")
        if base.count(".") < 1:
            return []

        found = await self._brute_force(base)
        if not found:
            return []

        lines = "\n".join(f"  {sub} → {ip}" for sub, ip in sorted(found))
        return [FindingData(
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
        )]

    async def _brute_force(self, base_domain: str) -> list[tuple[str, str]]:
        sem = asyncio.Semaphore(_MAX_CONCURRENT)
        loop = asyncio.get_event_loop()
        results: list[tuple[str, str]] = []

        async def resolve(prefix: str) -> None:
            fqdn = f"{prefix}.{base_domain}"
            async with sem:
                try:
                    ip = await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, fqdn),
                        timeout=_DNS_TIMEOUT,
                    )
                    results.append((fqdn, ip))
                except Exception:
                    pass

        await asyncio.gather(*[resolve(p) for p in _WORDLIST])
        return results


def _is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        return False
