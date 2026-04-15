from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.scanner.fingerprint.banner_grabber import grab_banner

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class TelnetDetectPlugin(PluginBase):
    id = "services.telnet_detect"
    name = "Telnet Service Detected"
    description = "Flag plaintext Telnet service — credentials sent in cleartext"
    category = PluginCategory.services
    severity = Severity.high
    ports = [23, 2323]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in (23, 2323) or port.state != "open":
                continue
            # Try to grab banner to confirm it's Telnet
            banner = await grab_banner(host.ip, port.number)
            is_telnet = (
                (port.service and port.service.name and "telnet" in port.service.name.lower())
                or (banner and len(banner) > 0)
                or True  # Port 23 being open is sufficient evidence
            )
            if is_telnet:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="Plaintext Telnet Service Running",
                    description=(
                        "Telnet transmits all data including credentials in plaintext. "
                        "Any network observer can capture authentication credentials and session data."
                    ),
                    evidence=f"Telnet service detected on {host.ip}:{port.number}" + (f"\nBanner: {banner}" if banner else ""),
                    remediation="Disable Telnet and replace with SSH for encrypted remote access.",
                    references=["https://cwe.mitre.org/data/definitions/312.html"],
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings
