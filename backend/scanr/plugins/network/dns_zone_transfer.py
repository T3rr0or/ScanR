"""Domain-level DNS AXFR check for external recon scans."""
from __future__ import annotations

import socket
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.scanner.discovery.dns_resolver import attempt_zone_transfer

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host


class DomainZoneTransferPlugin(PluginBase):
    id = "network.dns_zone_transfer"
    name = "DNS Zone Transfer"
    description = "Attempt AXFR zone transfer for domain targets"
    category = PluginCategory.network
    severity = Severity.high
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        domain = _root_domain(host.hostname or "")
        if not domain:
            return []

        records = await attempt_zone_transfer(domain)
        if not records:
            return []

        return [FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title=f"DNS Zone Transfer Allowed: {domain}",
            description=(
                "A nameserver allowed AXFR zone transfer for the domain. "
                "This can expose hidden hosts, environment names, third-party services, and internal naming patterns."
            ),
            evidence=f"Zone transfer returned {len(records)} records:\n" + "\n".join(records[:50]),
            remediation="Restrict AXFR to authorized secondary nameservers only and verify DNS server ACLs.",
            references=["https://cwe.mitre.org/data/definitions/200.html"],
            protocol="tcp",
            peer_review_command=f"dig AXFR {_q(domain)} @$(dig +short NS {_q(domain)} | head -n1)",
        )]


def _root_domain(hostname: str) -> str | None:
    hostname = hostname.strip().lower().rstrip(".").removeprefix("*.")
    if not hostname or _is_ip(hostname):
        return None
    parts = hostname.split(".")
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


def _is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def _q(value: str) -> str:
    import shlex
    return shlex.quote(value)
