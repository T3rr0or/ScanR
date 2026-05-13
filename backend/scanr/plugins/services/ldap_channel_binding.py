from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class LdapChannelBindingPlugin(PluginBase):
    id = "services.ldap_channel_binding"
    name = "LDAP Channel Binding / LDAPS Posture"
    description = "Flag LDAP endpoints where channel binding hardening cannot be inferred or LDAPS is absent"
    category = PluginCategory.services
    severity = Severity.high
    ports = [389, 636]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        openp = set(_open(host, {389, 636}))
        if 389 in openp and 636 not in openp:
            return [_finding(self.id, Severity.high, "LDAP Exposed Without LDAPS", "Domain LDAP is reachable on 389 but LDAPS was not discovered, increasing downgrade and NTLM relay risk where signing/channel binding are not enforced.", "TCP/389 open; TCP/636 not open in scan results", "Enable LDAPS, require LDAP signing, and enforce LDAP channel binding on domain controllers.", 389, ["https://support.microsoft.com/help/4520412"])]
        return []

