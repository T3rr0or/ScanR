from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable, Protocol

from scanr.utils.ip_utils import canonical_ip, is_valid_hostname


class ExclusionLike(Protocol):
    type: str
    value: str


def _normalise_hostname(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _parse_ports(value: str) -> set[int]:
    """Parse comma-separated ports/ranges, accepting tcp/443 and 443/tcp."""
    ports: set[int] = set()
    for raw_part in value.split(","):
        part = raw_part.strip().lower()
        if not part:
            raise ValueError("empty port exclusion")
        if "/" in part:
            left, right = part.split("/", 1)
            if left in {"tcp", "udp"}:
                part = right
            elif right in {"tcp", "udp"}:
                part = left
            else:
                raise ValueError(f"invalid port exclusion: {raw_part!r}")
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError(f"invalid port exclusion: {raw_part!r}")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"port exclusion ends before it starts: {raw_part!r}")
            candidates: Iterable[int] = range(start, end + 1)
        else:
            if not part.isdigit():
                raise ValueError(f"invalid port exclusion: {raw_part!r}")
            candidates = (int(part),)
        for port in candidates:
            if not 1 <= port <= 65_535:
                raise ValueError(f"port exclusion out of range: {port}")
            ports.add(port)
    return ports


@dataclass(frozen=True)
class ExclusionPolicy:
    """Immutable scope guardrail compiled from a scan's persisted exclusions."""

    exact_ips: frozenset[str] = frozenset()
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    exact_hosts: frozenset[str] = frozenset()
    host_suffixes: tuple[str, ...] = ()
    ports: frozenset[int] = frozenset()

    @classmethod
    def from_records(cls, records: Iterable[ExclusionLike]) -> "ExclusionPolicy":
        exact_ips: set[str] = set()
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        exact_hosts: set[str] = set()
        host_suffixes: set[str] = set()
        ports: set[int] = set()

        for record in records:
            kind = record.type.strip().lower()
            value = record.value.strip()
            if kind == "ip":
                canon = canonical_ip(value)
                if canon is None:
                    raise ValueError(f"invalid IP exclusion: {value!r}")
                exact_ips.add(canon)
            elif kind == "cidr":
                try:
                    networks.append(ipaddress.ip_network(value, strict=False))
                except ValueError as exc:
                    raise ValueError(f"invalid CIDR exclusion: {value!r}") from exc
            elif kind == "host":
                hostname = _normalise_hostname(value)
                wildcard = hostname.startswith("*.")
                candidate = hostname[2:] if wildcard else hostname
                if not is_valid_hostname(candidate):
                    raise ValueError(f"invalid host exclusion: {value!r}")
                if wildcard:
                    host_suffixes.add(candidate)
                else:
                    exact_hosts.add(candidate)
            elif kind == "port":
                ports.update(_parse_ports(value))
            else:
                raise ValueError(f"unsupported exclusion type: {record.type!r}")

        return cls(
            exact_ips=frozenset(exact_ips),
            networks=tuple(networks),
            exact_hosts=frozenset(exact_hosts),
            host_suffixes=tuple(sorted(host_suffixes)),
            ports=frozenset(ports),
        )

    def excludes_ip(self, value: str) -> bool:
        canon = canonical_ip(value)
        if canon is None:
            return False
        if canon in self.exact_ips:
            return True
        address = ipaddress.ip_address(canon)
        return any(address.version == network.version and address in network for network in self.networks)

    def excludes_hostname(self, value: str | None) -> bool:
        if not value:
            return False
        hostname = _normalise_hostname(value)
        if hostname in self.exact_hosts:
            return True
        return any(hostname.endswith(f".{suffix}") for suffix in self.host_suffixes)

    def excludes_host(self, ip_or_host: str, hostname: str | None = None) -> bool:
        return (
            self.excludes_ip(ip_or_host)
            or self.excludes_hostname(ip_or_host)
            or self.excludes_hostname(hostname)
        )

    def excludes_port(self, port: int) -> bool:
        return int(port) in self.ports

    def intersects_network(self, value: str) -> bool:
        """True when allowing this whole CIDR would re-allow an exclusion."""
        try:
            candidate = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        for exact in self.exact_ips:
            address = ipaddress.ip_address(exact)
            if address.version == candidate.version and address in candidate:
                return True
        return any(
            network.version == candidate.version and network.overlaps(candidate)
            for network in self.networks
        )

    async def excludes_target(self, target: str, *, resolve: bool = True) -> bool:
        """Match the literal target and, for hostnames, every current DNS answer."""
        if self.excludes_host(target):
            return True
        if not resolve or canonical_ip(target) is not None or not (self.exact_ips or self.networks):
            return False
        try:
            infos = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(target, None, type=socket.SOCK_STREAM),
                timeout=5.0,
            )
        except (OSError, UnicodeError, asyncio.TimeoutError):
            return False
        return any(self.excludes_ip(str(info[4][0])) for info in infos)

    async def filter_targets(
        self, targets: list[str], *, resolve: bool = True
    ) -> tuple[list[str], list[str]]:
        """Return (allowed, excluded), preserving input order."""
        decisions = await asyncio.gather(*(
            self.excludes_target(target, resolve=resolve) for target in targets
        ))
        allowed = [target for target, excluded in zip(targets, decisions, strict=True) if not excluded]
        excluded = [target for target, excluded in zip(targets, decisions, strict=True) if excluded]
        return allowed, excluded
