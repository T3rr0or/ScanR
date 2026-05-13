from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class AdcsEnumPlugin(PluginBase):
    id = "services.adcs_enum"
    name = "AD CS Web Enrollment Exposure"
    description = "Detect exposed Microsoft AD CS web enrollment endpoints"
    category = PluginCategory.services
    severity = Severity.high
    requires_auth = True
    ports = [80, 443, 8080, 8443]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        for port in _open(host, set(self.ports)):
            got = await _http_get(context, host.ip, port, "/certsrv/")
            if not got:
                continue
            url, resp = got
            body = resp.text[:3000].lower()
            auth = resp.headers.get("www-authenticate", "").lower()
            if "certsrv" in body or "certificate services" in body or "ntlm" in auth:
                return [_finding(self.id, Severity.high, "AD CS Web Enrollment Exposed", "Microsoft AD CS web enrollment is reachable. In AD environments this can contribute to ESC8/NTLM relay certificate abuse when EPA/signing controls are weak.", f"{url} returned HTTP {resp.status_code}; auth={auth[:120]}", "Restrict /certsrv to trusted admin networks, enforce HTTPS, EPA/channel binding, and audit templates for ESC1-ESC8 conditions.", port, ["https://specterops.io/blog/2021/06/17/certified-pre-owned/"])]
        return []

