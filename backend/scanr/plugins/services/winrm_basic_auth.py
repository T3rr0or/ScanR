from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class WinRMBasicAuthPlugin(PluginBase):
    id = "services.winrm_basic_auth"
    name = "WinRM Basic Authentication Exposure"
    description = "Detect WinRM endpoints advertising Basic authentication"
    category = PluginCategory.services
    severity = Severity.high
    ports = [5985, 5986]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        for port in _open(host, {5985, 5986}):
            got = await _http_get(context, host.ip, port, "/wsman", https=(port == 5986))
            if got:
                url, resp = got
                auth = resp.headers.get("www-authenticate", "")
                if "basic" in auth.lower():
                    sev = Severity.critical if port == 5985 else Severity.high
                    return [_finding(self.id, sev, "WinRM Basic Authentication Advertised", "WinRM advertises Basic authentication; over HTTP this can expose credentials to interception.", f"{url}: WWW-Authenticate={auth}", "Disable Basic authentication for WinRM, require Kerberos/Negotiate over HTTPS, and restrict WinRM to admin networks.", port)]
        return []

