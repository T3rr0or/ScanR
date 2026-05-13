from __future__ import annotations

from scanr.plugins.web._pentest_common import *


class JwtExtendedPlugin(PluginBase):
    id = "web.jwt_extended"
    name = "JWT Extended Checks"
    description = "Detect exposed JWKS and weak JWT header patterns"
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS

    PATHS = ["/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration", "/"]
    JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*")

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        async for port, url, resp in _web_responses(context, host, self.PATHS):
            text = resp.text[:50000]
            if "jwks" in url and resp.status_code < 400:
                try:
                    jwks = resp.json()
                    keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
                    weak = [k for k in keys if str(k.get("alg", "")).lower() in {"none", "hs256"} or not k.get("kid")]
                    if weak:
                        findings.append(FindingData(
                            plugin_id=self.id,
                            severity=Severity.high,
                            title="Weak JWKS Key Metadata",
                            description="JWKS endpoint contains keys with weak algorithms or missing key IDs.",
                            evidence=f"{url}: {len(weak)} weak key metadata entries",
                            remediation="Use asymmetric signing algorithms such as RS256/ES256 and unique non-user-controlled key IDs.",
                            references=["https://portswigger.net/web-security/jwt"],
                            port_number=port,
                            protocol="tcp",
                        ))
                        break
                except Exception:
                    pass
            for token in self.JWT_RE.findall(text)[:3]:
                try:
                    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
                except Exception:
                    continue
                issues = []
                if str(header.get("alg", "")).lower() == "none":
                    issues.append("alg=none")
                if any(x in str(header.get("kid", "")).lower() for x in ["../", "http://", "https://"]):
                    issues.append("suspicious kid")
                if issues:
                    findings.append(FindingData(
                        plugin_id=self.id,
                        severity=Severity.high,
                        title="Weak JWT Header Pattern",
                        description="A JWT observed in a response uses risky header values.",
                        evidence=f"{url}: {', '.join(issues)}",
                        remediation="Reject alg=none, pin accepted algorithms server-side, and do not use user-controlled kid values for file/URL lookup.",
                        references=["https://portswigger.net/web-security/jwt"],
                        port_number=port,
                        protocol="tcp",
                    ))
                    return findings
        return findings

