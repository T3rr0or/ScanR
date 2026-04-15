from __future__ import annotations

import asyncio
import logging
import socket

import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)


async def resolve_hostname(hostname: str) -> list[str]:
    """Resolve hostname to list of IPs (async wrapper)."""
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None)
        return list({info[4][0] for info in infos})
    except socket.gaierror:
        return []


async def reverse_lookup(ip: str) -> str | None:
    """Resolve IP to hostname."""
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR")
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


async def attempt_zone_transfer(domain: str) -> list[str]:
    """Attempt AXFR zone transfer. Returns list of record strings."""
    import dns.query
    import dns.zone

    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        records: list[str] = []
        for ns in ns_answers:
            ns_ip = str(dns.resolver.resolve(str(ns), "A")[0])
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                for name in zone.nodes:
                    records.append(f"{name}.{domain}")
                if records:
                    return records
            except Exception:
                continue
        return []
    except Exception:
        return []
