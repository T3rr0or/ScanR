from __future__ import annotations

import ipaddress
import re
from typing import Iterator


def expand_targets(value: str) -> Iterator[str]:
    """Yield individual IP addresses from a target specification."""
    value = value.strip()

    # CIDR notation
    if "/" in value:
        net = ipaddress.ip_network(value, strict=False)
        if net.num_addresses > 65536:  # reject anything larger than /16
            raise ValueError(f"CIDR block too large: {value} ({net.num_addresses} addresses, max /16)")
        for host in net.hosts():
            yield str(host)
        return

    # Range notation: 10.0.0.1-10.0.0.50 or 10.0.0.1-50
    range_match = re.match(r"^([\d.]+)-([\d.]+)$", value)
    if range_match:
        start_str, end_str = range_match.groups()
        try:
            start = ipaddress.IPv4Address(start_str)
            # Support short form: 10.0.0.1-50
            if "." not in end_str:
                base = ".".join(start_str.split(".")[:3])
                end_str = f"{base}.{end_str}"
            end = ipaddress.IPv4Address(end_str)
            current = int(start)
            stop = int(end)
            while current <= stop:
                yield str(ipaddress.IPv4Address(current))
                current += 1
            return
        except ValueError:
            pass

    # Single IP — validate and yield
    try:
        ipaddress.ip_address(value)
        yield value
        return
    except ValueError:
        pass

    # Hostname — validate before yielding (defence against future shell=True regressions)
    if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', value):
        raise ValueError(f"Invalid target: {value!r}")
    yield value


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# Hostnames that always resolve to the local host or cloud metadata services
# and must never be scanned, regardless of deployment configuration.
_FORBIDDEN_HOSTNAMES = {
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
}


def is_forbidden_target(value: str, extra_denylist: set[str] | None = None) -> bool:
    """Return True if a target points at the scanner's own infrastructure.

    Rejects loopback, link-local (including 169.254.169.254 cloud metadata),
    unspecified, multicast, and reserved addresses, plus a configurable set of
    infrastructure hostnames. This is a scope guardrail to stop a scan from
    pointing at the scanner host, its database/redis, or a cloud metadata
    endpoint — never a substitute for the operator's own authorization.
    """
    v = value.strip().lower().rstrip(".")
    if not v:
        return False
    if v in _FORBIDDEN_HOSTNAMES:
        return True
    if extra_denylist and v in extra_denylist:
        return True
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return False  # plain hostname not on the denylist — allowed
    return bool(
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
        or addr.is_reserved
    )


def classify_target(value: str) -> str:
    """Return TargetType string for a raw target value."""
    value = value.strip()
    if "/" in value:
        return "cidr"
    if re.match(r"^[\d.]+-[\d.]+$", value):
        return "range"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "hostname"
