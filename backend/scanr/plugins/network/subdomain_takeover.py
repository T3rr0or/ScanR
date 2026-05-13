from __future__ import annotations

from scanr.plugins.network._pentest_common import *


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
        try:
            async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=True, **context.proxy_config()) as client:
                resp = await client.get(f"http://{domain}/")
                text = resp.text[:5000].lower()
                body_hit = any(marker in text for marker in TAKEOVER_FINGERPRINTS[provider])
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

