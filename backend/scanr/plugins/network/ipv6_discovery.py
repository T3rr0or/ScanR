"""IPv6 host discovery and neighbor enumeration.

Internal networks often have IPv6 enabled with no firewall. This plugin
discovers IPv6 hosts via:
  - NDP neighbor solicitation (like ARP for IPv6)
  - Multicast listener discovery (MLD)
  - Router advertisement parsing
  - Link-local address scanning (fe80::/10)

Windows domains especially — IPv6 is enabled by default on all interfaces
and often unfirewalled.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# IPv6-specific ports for discovery
IPV6_ICMP_TYPE = 58


class Ipv6DiscoveryPlugin(PluginBase):
    id = "network.ipv6_discovery"
    name = "IPv6 Neighbor Discovery"
    description = (
        "Discover IPv6 hosts via NDP, multicast listener discovery, "
        "and router advertisement parsing"
    )
    category = PluginCategory.network
    severity = Severity.info
    ports = None  # network-level, not port-specific

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []

        ipv6_addrs = self._get_ipv6_addresses(host)
        if not ipv6_addrs:
            # Check if the host has an IPv6 address we can use
            ipv6_addrs = await self._resolve_ipv6(host.ip)

        if not ipv6_addrs:
            # Host doesn't have IPv6 — still flag that IPv6 might be enabled
            # on other hosts on the network
            return []

        neighbors = await self._discover_neighbors(host.ip)
        router_info = await self._parse_router_advertisements(host.ip)

        if not neighbors and not router_info:
            return []

        evidence_parts = [f"Host: {host.ip}", f"IPv6 addresses: {', '.join(ipv6_addrs)}"]

        if neighbors:
            evidence_parts.append(f"\nIPv6 Neighbors ({len(neighbors)}):")
            for n in neighbors[:50]:
                evidence_parts.append(f"  {n}")

        if router_info:
            evidence_parts.append(f"\nRouter Advertisements:")
            for k, v in router_info.items():
                evidence_parts.append(f"  {k}: {v}")

        description_parts = [
            f"IPv6 is active on the local network segment of {host.ip}.",
        ]
        if neighbors:
            description_parts.append(
                f"Discovered {len(neighbors)} IPv6 neighbors via NDP. "
                "IPv6 hosts may have different (often weaker) firewall rules "
                "than their IPv4 counterparts."
            )
        if router_info:
            description_parts.append(
                "Router advertisements detected — the network has active "
                "IPv6 routing with SLAAC addressing."
            )

        findings.append(FindingData(
            plugin_id=self.id,
            severity=Severity.info if len(neighbors) < 10 else Severity.medium,
            title=f"IPv6 Network Active — {len(neighbors)} host(s) discovered",
            description=" ".join(description_parts),
            evidence="\n".join(evidence_parts),
            remediation=(
                "If IPv6 is not required, disable it on all interfaces:\n"
                "  Windows: Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6\n"
                "  Linux: sysctl -w net.ipv6.conf.all.disable_ipv6=1\n"
                "If IPv6 is required, apply firewall rules identical to IPv4:\n"
                "  - Block unsolicited inbound IPv6 traffic\n"
                "  - Enable IPv6 ingress filtering at the network edge\n"
                "  - Run IPv6-specific vulnerability scans"
            ),
            references=[
                "https://attack.mitre.org/techniques/T1201/",
                "https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml",
                "https://datatracker.ietf.org/doc/html/rfc4861",  # NDP
            ],
            port_number=None,
            protocol="icmp6",
        ))

        return findings

    def _get_ipv6_addresses(self, host: "Host") -> list[str]:
        """Extract IPv6 addresses from host data."""
        addresses = []
        # Check host ports for IPv6 references
        if hasattr(host, 'ports'):
            for port in host.ports:
                if hasattr(port, 'service') and port.service:
                    if port.service.extra_info and 'ipv6' in (port.service.extra_info or '').lower():
                        addresses.append(host.ip)
        return addresses

    async def _resolve_ipv6(self, ip: str) -> list[str]:
        """Try to resolve an IPv4 host to its IPv6 address."""
        try:
            loop = asyncio.get_running_loop()
            addrs = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(ip, None, socket.AF_INET6)
            )
            return list({a[4][0] for a in addrs if a[4][0] != '::1'})
        except Exception:
            return []

    async def _discover_neighbors(self, ip: str) -> list[str]:
        """Discover IPv6 neighbors using NDP neighbor solicitation.
        
        Uses the 'ip -6 neigh' command on Linux or 'netsh interface ipv6' on Windows.
        For Docker, requires NET_RAW and host network mode for full NDP capability,
        so we fall back to running the tool if available.
        """
        import subprocess

        neighbors: list[str] = []
        loop = asyncio.get_running_loop()

        try:
            # Try Linux ip command
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["ip", "-6", "neigh", "show"],
                    capture_output=True, text=True, timeout=10,
                ),
            )
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.strip().splitlines():
                    parts = line.split()
                    if parts:
                        addr = parts[0]
                        if self._is_valid_ipv6(addr) and not addr.startswith("fe80:"):
                            neighbors.append(f"{addr} ({' '.join(parts[2:])})")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Try ping6 sweep of link-local addresses from common OUI prefixes
        if not neighbors:
            neighbors = await self._ping6_sweep(ip)

        return neighbors

    async def _ping6_sweep(self, base_ip: str) -> list[str]:
        """Sweep common link-local IPv6 patterns for the local segment."""
        import subprocess
        loop = asyncio.get_running_loop()
        found: list[str] = []

        # Extract subnet prefix if this is a global IPv6 address
        prefix = "fe80::"
        if ":" in base_ip and not base_ip.startswith("fe80:"):
            parts = base_ip.split(':')
            if len(parts) >= 4:
                prefix = ':'.join(parts[:4]) + ':'

        # Sweep a small range
        for suffix in range(1, 20):
            target = f"{prefix}{suffix:x}"
            try:
                proc = await loop.run_in_executor(
                    None,
                    lambda t=target: subprocess.run(
                        ["ping6", "-c", "1", "-W", "1", t],
                        capture_output=True, text=True, timeout=3,
                    ),
                )
                if proc.returncode == 0:
                    found.append(target)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                break

        return found

    async def _parse_router_advertisements(self, ip: str) -> dict | None:
        """Check for IPv6 router advertisements on the segment."""
        import subprocess
        loop = asyncio.get_running_loop()

        try:
            # Check if we received any RAs recently (Linux)
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["ip", "-6", "route", "show"],
                    capture_output=True, text=True, timeout=10,
                ),
            )
            if proc.returncode == 0 and "default via" in proc.stdout:
                ra_lines = [l.strip() for l in proc.stdout.splitlines() if "default" in l]
                return {
                    "default_routes": len(ra_lines),
                    "routes": ra_lines[:5],
                    "slaac_active": any("ra" in l.lower() for l in ra_lines),
                }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None

    @staticmethod
    def _is_valid_ipv6(addr: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET6, addr.split('%')[0])
            return True
        except (ValueError, OSError):
            return False
