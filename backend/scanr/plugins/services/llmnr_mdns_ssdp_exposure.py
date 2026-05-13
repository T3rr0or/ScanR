from __future__ import annotations

from scanr.plugins.services._pentest_common import *


class LlmnrMdnsSsdpExposurePlugin(PluginBase):
    id = "services.llmnr_mdns_ssdp_exposure"
    name = "LLMNR / mDNS / SSDP Exposure"
    description = "Detect link-local name discovery protocols that aid poisoning and device discovery"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [5355, 5353, 1900]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        found = _open(host, {5355, 5353, 1900})
        if found:
            return [_finding(self.id, Severity.medium, "Link-Local Discovery Protocol Exposed", "LLMNR, mDNS, or SSDP appears exposed. These protocols can leak host/service metadata and enable poisoning attacks on internal networks.", f"Open discovery ports: {', '.join(map(str, found))}", "Disable LLMNR/mDNS/SSDP where not required and enforce DNS-only name resolution on managed endpoints.", found[0])]
        return []

