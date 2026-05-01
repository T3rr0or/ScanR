"""Domain DNS reconnaissance for external and bug-bounty scans."""
from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA")


class DnsReconPlugin(PluginBase):
    id = "network.dns_recon"
    name = "DNS Reconnaissance"
    description = "Collect DNS A, AAAA, CNAME, MX, NS, TXT, and CAA records for domain targets"
    category = PluginCategory.network
    severity = Severity.info
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        hostname = (host.hostname or "").strip().lower().removeprefix("*.")
        if not hostname or _is_ip(hostname) or "." not in hostname:
            return []

        records = await _resolve_records(hostname)
        if not any(records.values()):
            return []

        lines: list[str] = []
        for rtype in _RECORD_TYPES:
            values = records.get(rtype, [])
            if values:
                lines.append(f"{rtype}:")
                lines.extend(f"  {value}" for value in values[:20])

        command = (
            "for type in A AAAA CNAME MX NS TXT CAA; "
            f"do printf '\\n%s\\n' \"$type\"; dig +short {_q(hostname)} \"$type\"; done"
        )
        return [FindingData(
            plugin_id=self.id,
            severity=Severity.info,
            title=f"DNS Records Collected: {hostname}",
            description=(
                "DNS records were collected for the domain. Review MX, NS, TXT, "
                "CAA, and CNAME records for exposed third-party services, takeover "
                "risk, SPF/DMARC posture, and certificate authority restrictions."
            ),
            evidence="\n".join(lines),
            remediation=(
                "Remove stale DNS records, verify third-party CNAME ownership, "
                "restrict certificate issuance with CAA, and maintain SPF/DMARC records."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
            ],
            protocol="udp",
            peer_review_command=command,
        )]


async def _resolve_records(hostname: str) -> dict[str, list[str]]:
    try:
        import dns.resolver
    except Exception:
        return await _socket_fallback(hostname)

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0

    async def query(rtype: str) -> tuple[str, list[str]]:
        try:
            answers = await asyncio.to_thread(resolver.resolve, hostname, rtype, raise_on_no_answer=False)
            values = sorted({str(answer).rstrip(".") for answer in answers})
            return rtype, values
        except Exception:
            return rtype, []

    results = await asyncio.gather(*(query(rtype) for rtype in _RECORD_TYPES))
    return dict(results)


async def _socket_fallback(hostname: str) -> dict[str, list[str]]:
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, hostname, None)
    except Exception:
        infos = []
    addresses = sorted({info[4][0] for info in infos})
    records = {rtype: [] for rtype in _RECORD_TYPES}
    for address in addresses:
        records["AAAA" if ":" in address else "A"].append(address)
    return records


def _is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def _q(value: str) -> str:
    import shlex
    return shlex.quote(value)
