from __future__ import annotations

from scanr.plugins.web._pentest_common import *


class OAuthOidcMisconfigPlugin(PluginBase):
    id = "web.oauth_oidc_misconfig"
    name = "OAuth/OIDC Discovery Misconfiguration"
    description = "Detect exposed OIDC metadata and weak discovery hints"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    PATHS = ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/oauth/.well-known/openid-configuration"]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        async for port, url, resp in _web_responses(context, host, self.PATHS):
            if resp.status_code >= 400:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            issues = []
            if "none" in data.get("id_token_signing_alg_values_supported", []):
                issues.append("supports alg none")
            if any("implicit" in str(x).lower() for x in data.get("grant_types_supported", [])):
                issues.append("implicit grant advertised")
            if any("token" == str(x).lower() for x in data.get("response_types_supported", [])):
                issues.append("token response type advertised")
            if not data.get("jwks_uri"):
                issues.append("missing jwks_uri")
            if issues:
                sev = Severity.high if "supports alg none" in issues else Severity.medium
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=sev,
                    title="Weak OAuth/OIDC Discovery Configuration",
                    description="OIDC/OAuth discovery metadata advertises risky options or incomplete signing key configuration.",
                    evidence=f"{url}: {', '.join(issues)}",
                    remediation="Disable implicit/token flows unless required, require strong signing algorithms, and publish a valid JWKS URI.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html"],
                    port_number=port,
                    protocol="tcp",
                ))
                break
        return findings

