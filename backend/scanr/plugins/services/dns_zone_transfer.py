from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.scanner.discovery.dns_resolver import attempt_zone_transfer

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class DnsZoneTransferPlugin(PluginBase):
    id = "services.dns_zone_transfer"
    name = "DNS Zone Transfer (AXFR)"
    description = "Attempt AXFR zone transfer from DNS servers"
    category = PluginCategory.services
    severity = Severity.high
    ports = [53]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number != 53 or port.state != "open":
                continue
            hostname = host.hostname or host.ip
            # Extract domain from hostname
            parts = hostname.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])
                records = await attempt_zone_transfer(domain)
                if records:
                    findings.append(FindingData(
                        plugin_id=self.id,
                        severity=Severity.high,
                        title="DNS Zone Transfer Allowed (AXFR)",
                        description=(
                            f"The DNS server allowed a full zone transfer (AXFR) for {domain}. "
                            "This exposes all DNS records, revealing internal hostnames, IPs, and network topology."
                        ),
                        evidence=f"Zone transfer returned {len(records)} records:\n" + "\n".join(records[:20]),
                        remediation="Restrict zone transfers to authorized secondary DNS servers only. Configure ACLs in your DNS server.",
                        references=["https://cwe.mitre.org/data/definitions/200.html"],
                        port_number=53,
                        protocol="tcp",
                    ))
        return findings
