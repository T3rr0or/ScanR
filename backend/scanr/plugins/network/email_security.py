from __future__ import annotations

from scanr.plugins.network._pentest_common import *


class EmailSecurityPlugin(PluginBase):
    id = "network.email_security"
    name = "Email Security DNS Policy"
    description = "Check SPF, DMARC, MTA-STS, TLS-RPT, and MX records"
    category = PluginCategory.network
    severity = Severity.medium
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        domain = _domain_for_host(host)
        if not domain or "." not in domain:
            return []
        # Check apex-like name only; subdomain mail policy can inherit DMARC.
        findings = []
        mx = await _resolve_txt(domain, "MX")
        if not mx:
            return []
        txt = await _resolve_txt(domain, "TXT")
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        dmarc = await _resolve_txt(f"_dmarc.{domain}", "TXT")
        mta_sts = await _resolve_txt(f"_mta-sts.{domain}", "TXT")
        tls_rpt = await _resolve_txt(f"_smtp._tls.{domain}", "TXT")

        issues = []
        if not spf:
            issues.append("missing SPF")
        if not dmarc:
            issues.append("missing DMARC")
        elif any("p=none" in r.lower() for r in dmarc):
            issues.append("DMARC policy p=none")
        if not mta_sts:
            issues.append("missing MTA-STS")
        if not tls_rpt:
            issues.append("missing TLS-RPT")
        if issues:
            findings.append(FindingData(
                plugin_id=self.id,
                severity=Severity.medium,
                title="Weak Email Security DNS Policy",
                description="Domain accepts mail but lacks one or more anti-spoofing or transport-security DNS policies.",
                evidence=f"{domain}: {', '.join(issues)}",
                remediation="Publish SPF, enforce DMARC (quarantine/reject), and deploy MTA-STS/TLS-RPT for mail transport visibility.",
                references=["https://dmarc.org/", "https://datatracker.ietf.org/doc/html/rfc8461"],
                protocol="dns",
            ))
        return findings

