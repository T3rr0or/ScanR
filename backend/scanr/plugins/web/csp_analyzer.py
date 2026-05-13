from __future__ import annotations

from scanr.plugins.web._pentest_common import *


class CspAnalyzerPlugin(PluginBase):
    id = "web.csp_analyzer"
    name = "Content Security Policy Analyzer"
    description = "Detect weak or missing CSP directives"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        async for port, url, resp in _web_responses(context, host, ["/"]):
            csp = resp.headers.get("content-security-policy", "")
            if not csp:
                continue  # web.http_headers already reports missing CSP
            low = csp.lower()
            issues = []
            if "unsafe-inline" in low:
                issues.append("unsafe-inline")
            if "unsafe-eval" in low:
                issues.append("unsafe-eval")
            if re.search(r"(?:script-src|default-src)[^;]*\*", low):
                issues.append("wildcard script/default source")
            if "frame-ancestors" not in low:
                issues.append("missing frame-ancestors")
            if "object-src" not in low:
                issues.append("missing object-src")
            if issues:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Weak Content Security Policy",
                    description="CSP is present but permits risky script execution or lacks key containment directives.",
                    evidence=f"{url}: {', '.join(issues)}; CSP={csp[:500]}",
                    remediation="Remove unsafe-inline/unsafe-eval where possible, avoid wildcards, and add frame-ancestors/object-src restrictions.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                    port_number=port,
                    protocol="tcp",
                ))
                break
        return findings

