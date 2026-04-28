from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

DEFAULT_COMMUNITIES = ["public", "private", "community", "manager", "admin", "snmp", "cisco", "monitor"]


class SnmpCommunityPlugin(PluginBase):
    id = "services.snmp_community"
    name = "SNMP Default Community Strings"
    description = "Brute-force common SNMP v1/v2c community strings"
    category = PluginCategory.services
    severity = Severity.high
    ports = [161]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number != 161 or port.state != "open":
                continue
            found = await self._try_communities(host.ip)
            for community, sys_descr in found:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title=f"SNMP Default Community String: '{community}'",
                    description=(
                        f"SNMP community string '{community}' is accepted on this device. "
                        "SNMP v1/v2c community strings are sent in cleartext and provide access to sensitive device information."
                    ),
                    evidence=f"Community '{community}' accepted. sysDescr: {sys_descr}",
                    remediation=(
                        "Change all SNMP community strings to strong, unique values. "
                        "Upgrade to SNMPv3 with authentication and encryption. "
                        "Restrict SNMP access to management network only."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/522.html"],
                    port_number=161,
                    protocol="udp",
                ))
        return findings

    async def _try_communities(self, ip: str) -> list[tuple[str, str]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._snmp_sync, ip)

    def _snmp_sync(self, ip: str) -> list[tuple[str, str]]:
        found = []
        try:
            from pysnmp.hlapi import (
                CommunityData, ContextData, ObjectIdentity, ObjectType,
                SnmpEngine, UdpTransportTarget, getCmd,
            )
            engine = SnmpEngine()  # single engine instance — reused across all community probes
            for community in DEFAULT_COMMUNITIES:
                try:
                    iterator = getCmd(
                        engine,
                        CommunityData(community, mpModel=1),  # SNMPv2c
                        UdpTransportTarget((ip, 161), timeout=2, retries=0),
                        ContextData(),
                        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
                    )
                    error_indication, error_status, _, var_binds = next(iterator)
                    if not error_indication and not error_status:
                        sys_descr = str(var_binds[0][1]) if var_binds else ""
                        found.append((community, sys_descr))
                except Exception:
                    continue
        except ImportError:
            logger.warning("pysnmp not available, skipping SNMP community check")
        return found
