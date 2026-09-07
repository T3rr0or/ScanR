from __future__ import annotations

import asyncio
import ipaddress
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
        # str(): typeshed's sockaddr union includes a non-str form, so the
        # element widens to str | int; for these families it is already a string.
        return list({str(info[4][0]) for info in infos})
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


async def attempt_zone_transfer(domain: str, server_ip: str) -> list[str]:
    """Attempt AXFR against one already-authorized scanned DNS server.

    The caller must pass the numeric address from the current ``Host``. Never
    discover or follow the zone's NS records here: those nameservers can be
    unrelated third parties outside the approved scan scope.
    """
    import dns.query
    import dns.zone

    try:
        authorized_server = str(ipaddress.ip_address(server_ip))
    except ValueError:
        return []

    def _transfer() -> list[str]:
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(authorized_server, domain, timeout=5)
            )
            return [f"{name}.{domain}" for name in zone.nodes]
        except Exception:
            return []

    return await asyncio.to_thread(_transfer)
