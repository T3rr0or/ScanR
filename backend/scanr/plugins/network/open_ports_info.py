from __future__ import annotations

import json
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host


class OpenPortsInfoPlugin(PluginBase):
    id = "network.open_ports_info"
    name = "Open Ports Inventory"
    description = "Document all discovered open ports and services"
    category = PluginCategory.network
    severity = Severity.info
    ports = None  # all ports

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        open_ports = [p for p in host.ports if p.state == "open"]
        if not open_ports:
            return []

        port_list = []
        for p in sorted(open_ports, key=lambda x: x.number):
            entry = f"{p.number}/{p.protocol}"
            if p.service and p.service.name:
                entry += f" ({p.service.name}"
                if p.service.product:
                    entry += f" {p.service.product}"
                if p.service.version:
                    entry += f" {p.service.version}"
                entry += ")"
            port_list.append(entry)

        return [FindingData(
            plugin_id=self.id,
            severity=Severity.info,
            title=f"Open Ports: {len(open_ports)} port(s) discovered",
            description=f"The host has {len(open_ports)} open port(s). Review to confirm all services are intentional.",
            evidence="Open ports:\n" + "\n".join(port_list),
            remediation="Close or firewall any unnecessary ports to reduce attack surface.",
        )]
