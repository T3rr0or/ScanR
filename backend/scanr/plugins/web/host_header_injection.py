from __future__ import annotations

from scanr.plugins.web._pentest_common import *


class HostHeaderInjectionPlugin(PluginBase):
    id = "web.host_header_injection"
    name = "Host Header Injection"
    description = "Detect reflected or trusted Host/X-Forwarded-Host headers"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        marker = "scanr-host-header-test.invalid"
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            url = f"{scheme}://{host.ip}:{port.number}/"
            resp = await _fetch(context, url, headers={"Host": marker, "X-Forwarded-Host": marker})
            if not resp:
                continue
            body = resp.text[:10000].lower()
            loc = resp.headers.get("location", "").lower()
            if marker in body or marker in loc:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Host Header Reflected or Trusted",
                    description="Application reflects or trusts attacker-controlled Host/X-Forwarded-Host data, which can enable cache poisoning or password reset poisoning.",
                    evidence=f"{url} reflected {marker} in {'Location header' if marker in loc else 'response body'}",
                    remediation="Validate Host against an allowlist and ignore untrusted X-Forwarded-Host unless set by a trusted proxy.",
                    references=["https://portswigger.net/web-security/host-header"],
                    port_number=port.number,
                    protocol="tcp",
                ))
                break
        return findings

