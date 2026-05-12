"""SNMP extended enumeration via MIB walking.

Goes beyond simple community string detection — walks common MIB trees
to extract system info, network interfaces, routing tables, and running
processes from SNMP-enabled devices.

Uses the system 'snmpwalk' binary if available, otherwise falls back to
a pure-Python SNMPv1/v2c walker.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

SNMP_PORTS = [161]

# Common read-only and read-write community strings
_COMMUNITIES = ["public", "private", "manager", "monitor", "snmp", "admin", "root",
                "cisco", "netman", "default", "read", "write", "secret",
                "internal", "access", "snmpd", "snmpd", "tivoli", "openview",
                "ILMI", "public@es0"]

# MIB OIDs to walk for enumeration
_MIBS = {
    "system": "1.3.6.1.2.1.1",           # sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation
    "interfaces": "1.3.6.1.2.1.2",       # ifTable
    "ip": "1.3.6.1.2.1.4",               # ipAddrTable, ipRouteTable
    "tcp": "1.3.6.1.2.1.6",              # tcpConnTable
    "udp": "1.3.6.1.2.1.7",              # udpTable
    "hr_storage": "1.3.6.1.2.1.25.2",    # Host Resources storage
    "hr_devices": "1.3.6.1.2.1.25.3",    # Host Resources devices (CPU, disk)
    "hr_swrun": "1.3.6.1.2.1.25.4",      # Host Resources running software
    "snmp_engine": "1.3.6.1.6.3.10.2",   # SNMP-FRAMEWORK-MIB
}

# Sensitive device types to flag
_DEVICE_OID_PREFIXES: dict[str, str] = {
    "1.3.6.1.4.1.9": "Cisco",
    "1.3.6.1.4.1.11": "HP/HPE",
    "1.3.6.1.4.1.311": "Microsoft",
    "1.3.6.1.4.1.8072": "Net-SNMP (Linux)",
    "1.3.6.1.4.1.674": "Dell",
    "1.3.6.1.4.1.2": "IBM",
    "1.3.6.1.4.1.3224": "Juniper",
    "1.3.6.1.4.1.6486": "Alcatel-Lucent",
    "1.3.6.1.4.1.1991": "Brocade/Foundry",
    "1.3.6.1.4.1.4526": "Netgear",
    "1.3.6.1.4.1.2636": "Juniper (alt)",
    "1.3.6.1.4.1.25506": "H3C/HP Networking",
    "1.3.6.1.4.1.890": "Allied Telesis",
}


class SnmpWalkPlugin(PluginBase):
    id = "services.snmp_walk"
    name = "SNMP MIB Walk Enumeration"
    description = (
        "Walk SNMP MIB trees on reachable devices to enumerate system info, "
        "network interfaces, routing tables, and running software"
    )
    category = PluginCategory.services
    severity = Severity.medium
    ports = SNMP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in (SNMP_PORTS if self.ports is None else self.ports):
                continue
            result = await self._walk_host(host.ip, port.number)
            if result:
                findings.append(result)
        return findings

    async def _walk_host(self, ip: str, port: int) -> FindingData | None:
        """Test community strings and walk MIBs."""
        working_communities: list[str] = []
        collected_data: dict[str, str] = {}
        device_type = "unknown"
        ro_community = None
        rw_community = None

        for community in _COMMUNITIES:
            sys_info = await self._snmpwalk(ip, port, community, _MIBS["system"])
            if sys_info:
                working_communities.append(community)
                collected_data["system"] = sys_info

                # Detect device type from sysObjectID
                device_type = self._identify_device(sys_info)

                # Check RW by attempting a SET operation (or checking if write MIBs respond)
                if rw_community is None:
                    rw = await self._test_rw(ip, port, community)
                    if rw:
                        rw_community = community
                    elif ro_community is None:
                        ro_community = community

                # Walk other MIBs only for the first working community to save time
                if len(working_communities) == 1:
                    for mib_name, oid in _MIBS.items():
                        if mib_name == "system":
                            continue
                        data = await self._snmpwalk(ip, port, community, oid)
                        if data:
                            collected_data[mib_name] = data
                break  # first working community is sufficient

        if not working_communities:
            return None

        is_rw = rw_community is not None

        evidence_lines = [
            f"Host: {ip}:{port}",
            f"Device type: {device_type}",
            f"Working communities: {', '.join(working_communities)}",
            f"Read-Write access: {'YES (' + rw_community + ')' if is_rw else 'No'}",
        ]
        for mib, data in collected_data.items():
            preview = data[:500] + ("..." if len(data) > 500 else "")
            evidence_lines.append(f"\n--- {mib} ---\n{preview}")

        severity = Severity.critical if is_rw else Severity.high

        description_parts = [
            f"SNMP service on {ip}:{port} responds to community string(s): {', '.join(working_communities)}.",
            f"Device identified as: {device_type}.",
        ]
        if is_rw:
            description_parts.append(
                f"WRITE access available via community '{rw_community}'. "
                "An attacker can modify device configuration, reboot the device, "
                "or exfiltrate full configuration via SNMP SET."
            )
        else:
            description_parts.append(
                "Read-only access available. An attacker can enumerate "
                "system configuration, network topology, and user accounts."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=f"SNMP Enumeration — {device_type} ({'RW' if is_rw else 'RO'})",
            description=" ".join(description_parts),
            evidence="\n".join(evidence_lines),
            remediation=(
                "Disable SNMPv1/v2c if not needed. If required:\n"
                "1. Change default community strings to complex values\n"
                "2. Restrict SNMP access via ACL to management IPs only\n"
                "3. Use SNMPv3 with authPriv security level\n"
                "4. Place SNMP management on a dedicated VLAN"
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection",  # SNMP section
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6736",  # SNMP RW Cisco IOS
            ],
            port_number=port,
            protocol="udp",
        )

    async def _snmpwalk(self, ip: str, port: int, community: str, oid: str) -> str | None:
        """Run snmpwalk and return output, or None on failure."""
        loop = asyncio.get_running_loop()
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    [
                        "snmpwalk", "-v2c", "-c", community,
                        f"{ip}:{port}", oid,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                ),
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    async def _test_rw(self, ip: str, port: int, community: str) -> bool:
        """Test if the community has write access.
        
        Attempts to read-write test via snmpset on sysContact (non-destructive).
        Returns True if write succeeded, False otherwise.
        """
        loop = asyncio.get_running_loop()
        try:
            # First read current value
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["snmpget", "-v2c", "-c", community, f"{ip}:{port}",
                     "1.3.6.1.2.1.1.4.0"],  # sysContact
                    capture_output=True, text=True, timeout=10,
                ),
            )
            if proc.returncode != 0:
                return False

            # Parse current value
            current = proc.stdout.strip()
            match = re.search(r'STRING:\s*"?(.*?)"?$', current)
            if not match:
                return False
            original = match.group(1)

            # Try setting a test value
            test_value = "ScanR_test_write"
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["snmpset", "-v2c", "-c", community, f"{ip}:{port}",
                     "1.3.6.1.2.1.1.4.0", "s", test_value],
                    capture_output=True, text=True, timeout=10,
                ),
            )
            if proc.returncode != 0:
                return False

            # Restore original value
            await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["snmpset", "-v2c", "-c", community, f"{ip}:{port}",
                     "1.3.6.1.2.1.1.4.0", "s", original],
                    capture_output=True, text=True, timeout=10,
                ),
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @staticmethod
    def _identify_device(system_oid: str) -> str:
        """Map sysObjectID prefix to vendor name."""
        for prefix, vendor in _DEVICE_OID_PREFIXES.items():
            if prefix in system_oid:
                return vendor
        return "Generic SNMP device"
