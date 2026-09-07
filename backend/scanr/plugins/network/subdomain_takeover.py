from __future__ import annotations

import logging

from scanr.plugins.network._pentest_common import *
from scanr.utils.safe_http import UnsafeHTTPDestination, pinned_async_client

logger = logging.getLogger(__name__)


class SubdomainTakeoverPlugin(PluginBase):
    id = "network.subdomain_takeover"
    name = "Subdomain Takeover Detection"
    description = "Detect dangling CNAME pointers to deprovisioned cloud services"
    category = PluginCategory.network
    severity = Severity.high
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        domain = _domain_for_host(host)
        if not domain or "." not in domain:
            return []

        def _cname():
            try:
                return str(dns.resolver.resolve(domain, "CNAME", lifetime=4.0)[0].target).rstrip(".").lower()
            except Exception:
                return None

        cname = await asyncio.to_thread(_cname)
        if not cname:
            return []
        provider = next((suffix for suffix in TAKEOVER_FINGERPRINTS if suffix in cname), None)
        if not provider:
            return []

        dangling = False
        try:
            await asyncio.to_thread(lambda: dns.resolver.resolve(cname, "A", lifetime=4.0))
        except Exception:
            dangling = True

        body_hit = False
        # A dangling CNAME is attacker-influenced and may point anywhere,
        # including inside our own infrastructure. Resolve and validate the
        # answer once, then pin to it, rather than letting a plain client
        # follow whatever the record currently says.
        try:
            proxy_config = context.proxy_config()
            url = f"http://{domain}/"
            if proxy_config:
                client = httpx.AsyncClient(
                    timeout=6.0, verify=False, follow_redirects=False, **proxy_config
                )
            else:
                client = await pinned_async_client(url, timeout=6.0, verify=False)
            async with client:
                resp = await client.get(url)
                text = resp.text[:5000].lower()
                body_hit = any(marker in text for marker in TAKEOVER_FINGERPRINTS[provider])
        except UnsafeHTTPDestination as exc:
            logger.debug("subdomain_takeover: refusing %s: %s", domain, exc)
        except Exception:
            pass

        if dangling or body_hit:
            return [FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title="Potential Subdomain Takeover",
                description="A subdomain CNAME points at a cloud/SaaS provider and appears unclaimed or unresolved.",
                evidence=f"{domain} CNAME -> {cname}; provider={provider}; dangling_dns={dangling}; provider_marker={body_hit}",
                remediation="Remove the DNS record or claim/provision the referenced service before exposing it publicly.",
                references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                protocol="dns",
            )]
        return []
