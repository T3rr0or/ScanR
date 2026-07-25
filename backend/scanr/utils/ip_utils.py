from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from functools import lru_cache
from typing import Iterator

logger = logging.getLogger(__name__)

_HOSTNAME_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


def canonical_ip(value: str) -> str | None:
    """Return ``value`` as a canonical IP string, or None if it is not an IP.

    Handles the legacy IPv4 encodings that ``ipaddress`` rejects but the C
    resolver still accepts — decimal (``2130706433``), hex (``0x7f000001``),
    octal (``017700000001``) and short forms (``127.1``) all resolve to
    127.0.0.1 through glibc's getaddrinfo. Without normalizing them, a
    string-based denylist check sees "just a hostname" and lets them through.
    ``socket.inet_aton`` accepts exactly that legacy set and rejects real
    hostnames, which is what makes it the right normalizer here.
    """
    v = value.strip()
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    try:
        return socket.inet_ntoa(socket.inet_aton(v))
    except (OSError, UnicodeEncodeError):
        return None


def is_valid_hostname(value: str) -> bool:
    """RFC-1123 hostname: dot-separated labels of 1-63 chars, each starting and
    ending with an alphanumeric, hyphens only inside a label. A trailing dot
    (FQDN form) is allowed. This rejects option-injection values like '-Pn',
    '--banners', or 'foo-' that would otherwise be passed as argv to scanner
    subprocesses."""
    v = value.strip().rstrip(".")
    if not v or len(v) > 253:
        return False
    return all(_HOSTNAME_LABEL_RE.match(label) for label in v.split("."))


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

    # Single IP — validate and yield. Legacy numeric forms ('127.1',
    # '0x7f000001') are normalized to dotted-quad so downstream denylist checks
    # and scanner arguments see a real address rather than a pseudo-hostname.
    canon = canonical_ip(value)
    if canon is not None:
        yield canon
        return

    # Hostname — validate before yielding (defence against option injection and
    # future shell=True regressions)
    if not is_valid_hostname(value):
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


@lru_cache(maxsize=8)
def _denylist_hostname_ips(denylist: frozenset[str]) -> frozenset[str]:
    """Resolve denylisted infrastructure hostnames to their IPs, once per process.

    The denylist is configured by hostname ('postgres', 'redis', ...), but those
    services sit on a private Docker network, and private ranges are legitimately
    scannable — so a target given as the container's bare IP bypassed a
    name-only check. Resolving the names closes that.

    Cached because is_forbidden_target runs per target in large scans and must not
    do DNS each time; container addresses are stable for the container's lifetime.
    Resolution failures are skipped (a name that does not resolve cannot be the
    IP an attacker reaches either).
    """
    ips: set[str] = set()
    for name in denylist:
        try:
            for info in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM):
                # sockaddr[0] is the address; typed str | int because sockaddr is
                # a union across address families.
                canon = canonical_ip(str(info[4][0]))
                if canon:
                    ips.add(canon)
        except (OSError, UnicodeError):
            logger.debug("Denylisted hostname %r does not resolve — skipping", name)
    return frozenset(ips)


def is_forbidden_target(value: str, extra_denylist: set[str] | None = None) -> bool:
    """Return True if a target points at the scanner's own infrastructure.

    Rejects loopback, link-local (including 169.254.169.254 cloud metadata),
    unspecified, multicast, and reserved addresses, plus a configurable set of
    infrastructure hostnames *and the addresses those names resolve to*. This is a
    scope guardrail to stop a scan from pointing at the scanner host, its
    database/redis, or a cloud metadata endpoint — never a substitute for the
    operator's own authorization.
    """
    v = value.strip().lower().rstrip(".")
    if not v:
        return False
    if v in _FORBIDDEN_HOSTNAMES:
        return True
    if extra_denylist and v in extra_denylist:
        return True
    # Normalize legacy numeric encodings so '127.1' / '2130706433' / '0x7f000001'
    # are checked as the loopback address they actually resolve to.
    canon = canonical_ip(v)
    if canon is None:
        return False  # plain hostname not on the denylist — allowed
    addr = ipaddress.ip_address(canon)
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
        or addr.is_reserved
    ):
        return True
    if extra_denylist and canon in _denylist_hostname_ips(frozenset(extra_denylist)):
        return True
    return False


async def resolve_and_check_target(hostname: str, extra_denylist: set[str] | None = None) -> bool:
    """Resolve a hostname via system DNS and return True if ANY address it
    resolves to is forbidden (loopback / link-local incl. cloud metadata /
    unspecified / multicast / reserved).

    The string-based is_forbidden_target check alone misses hostnames that
    resolve to internal infrastructure (e.g. a hostname pointing at 127.0.0.1
    or 169.254.169.254). Unresolvable hostnames return False — the connection
    itself will fail later (consistent with webhook URL validation).
    """
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):  # gaierror is an OSError subclass
        return False  # cannot resolve — connection will fail at scan time anyway
    for info in infos:
        if is_forbidden_target(info[4][0], extra_denylist):
            return True
    return False


def classify_target(value: str) -> str:
    """Return TargetType string for a raw target value."""
    value = value.strip()
    if "/" in value:
        return "cidr"
    if re.match(r"^[\d.]+-[\d.]+$", value):
        return "range"
    # canonical_ip (not ipaddress alone) so legacy numeric forms are classified
    # as the IPs they are, matching what expand_targets yields.
    return "ip" if canonical_ip(value) is not None else "hostname"
