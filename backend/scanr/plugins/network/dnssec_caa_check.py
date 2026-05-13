from __future__ import annotations

from scanr.plugins.network._pentest_common import *


class DnssecCaaCheckPlugin(PluginBase):
    id = "network.dnssec_caa_check"
    name = "DNSSEC / CAA Check"
    description = "Check DNSSEC, CAA, and wildcard DNS posture"
    category = PluginCategory.network
    severity = Severity.low
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        domain = _domain_for_host(host)
        if not domain or "." not in domain:
            return []

        issues = []
        caa = await _resolve_txt(domain, "CAA")
        dnskey = await _resolve_txt(domain, "DNSKEY")
        if not caa:
            issues.append("missing CAA")
        if not dnskey:
            issues.append("DNSSEC not detected")

        wildcard = False
        try:
            wild = f"scanr-wildcard-test-invalid.{domain}"
            await asyncio.to_thread(lambda: dns.resolver.resolve(wild, "A", lifetime=4.0))
            wildcard = True
        except Exception:
            pass
        if wildcard:
            issues.append("wildcard DNS enabled")

        if not issues:
            return []
        return [FindingData(
            plugin_id=self.id,
            severity=Severity.low,
            title="DNS Hardening Gaps",
            description="DNS zone lacks optional hardening controls or uses wildcard DNS.",
            evidence=f"{domain}: {', '.join(issues)}",
            remediation="Publish CAA records, enable DNSSEC where appropriate, and avoid broad wildcard DNS unless required.",
            references=["https://letsencrypt.org/docs/caa/", "https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
            protocol="dns",
        )]

