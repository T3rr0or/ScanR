from __future__ import annotations

from scanr.plugins.web._pentest_common import *


class CookieSecurityPlugin(PluginBase):
    id = "web.cookie_security"
    name = "Cookie Security Flags"
    description = "Detect cookies missing Secure, HttpOnly, or SameSite attributes"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        async for port, url, resp in _web_responses(context, host, ["/", "/login", "/admin"]):
            cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
            weak = []
            for c in cookies:
                low = c.lower()
                name = c.split("=", 1)[0]
                misses = []
                if "secure" not in low and url.startswith("https://"):
                    misses.append("Secure")
                if "httponly" not in low:
                    misses.append("HttpOnly")
                if "samesite" not in low:
                    misses.append("SameSite")
                if misses:
                    weak.append(f"{name} missing {', '.join(misses)}")
            if weak:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Cookie Missing Security Attributes",
                    description="Session or application cookies lack browser-enforced protections against theft or cross-site use.",
                    evidence=f"{url}: " + "; ".join(weak[:8]),
                    remediation="Set Secure on HTTPS cookies, HttpOnly on session cookies, and SameSite=Lax or Strict unless cross-site use is required.",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    port_number=port,
                    protocol="tcp",
                ))
                break
        return findings

