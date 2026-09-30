"""IPv6 discovery plugin placeholder.

The previous implementation inspected the ScanR worker's machine-wide
neighbor table and pinged link-local addresses. ScanContext does not currently
carry an authorized IPv6 network scope, so those results cannot be attributed
to the scanned host or safely constrained to the operator's targets.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host


class Ipv6DiscoveryPlugin(PluginBase):
    id = "network.ipv6_discovery"
    name = "IPv6 Neighbor Discovery"
    description = "IPv6 neighbor discovery is disabled until scans carry an explicit IPv6 network scope"
    category = PluginCategory.network
    severity = Severity.info
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        # Host-level scans can target a single address, while NDP state belongs
        # to the worker's interface. Until ScanContext carries an explicit IPv6
        # network scope and the plugin filters results against it, no neighbor
        # enumeration is safe to run here (including in an internal scan).
        return []
