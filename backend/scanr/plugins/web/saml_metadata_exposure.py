from __future__ import annotations

from scanr.plugins.web._pentest_common import *


class SamlMetadataExposurePlugin(PluginBase):
    id = "web.saml_metadata_exposure"
    name = "SAML Metadata Exposure"
    description = "Detect exposed SAML metadata with weak signing/encryption posture"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    PATHS = ["/saml/metadata", "/saml2/metadata", "/metadata", "/FederationMetadata/2007-06/FederationMetadata.xml"]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        async for port, url, resp in _web_responses(context, host, self.PATHS):
            text = resp.text[:20000]
            low = text.lower()
            if resp.status_code < 400 and ("entitydescriptor" in low or "saml" in low and "x509certificate" in low):
                issues = []
                if "keydescriptor use=\"signing\"" not in low:
                    issues.append("no explicit signing key")
                if "keydescriptor use=\"encryption\"" not in low:
                    issues.append("no explicit encryption key")
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium if issues else Severity.info,
                    title="SAML Metadata Exposed",
                    description="Public SAML metadata reveals identity provider/service provider configuration and certificates.",
                    evidence=f"{url} returned SAML metadata" + (f"; issues: {', '.join(issues)}" if issues else ""),
                    remediation="Limit metadata exposure if not required and ensure assertions/responses are signed and encrypted where appropriate.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html"],
                    port_number=port,
                    protocol="tcp",
                ))
                break
        return findings

