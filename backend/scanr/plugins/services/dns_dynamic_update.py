"""Unauthenticated DNS dynamic update (RFC 2136) detection.

A DNS server that accepts dynamic updates from anyone lets an attacker add or
overwrite records in the zone. That is name hijacking with no exploit involved:
point an existing host name at an attacker-controlled address to intercept its
traffic, or add a record like ``wpad`` or ``*`` to have clients volunteer their
credentials. On Active Directory DNS it is the ADIDNS attack — an unprivileged
position becomes domain-wide traffic interception.

**Nothing is written by this check.** RFC 2136 §3.4 requires a server to apply
policy before applying changes, so an UPDATE message carrying an *empty* update
section is processed for permission and then does nothing. The reply code alone
separates the three cases:

  * ``NOERROR``  — the server would have applied our update. Reportable.
  * ``REFUSED`` / ``NOTIMP`` — the server is authoritative and denies us. Correct.
  * ``NOTAUTH``  — wrong zone; try a shorter candidate.

Because the update section is empty, a permissive server has nothing to add, so a
``NOERROR`` is proof of authorization without leaving a record behind.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_OPCODE_UPDATE = 5
_TYPE_SOA = 6
_CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_NOTIMP = 4
RCODE_REFUSED = 5
RCODE_NOTAUTH = 9

_FLAG_QR = 0x8000

_UDP_TIMEOUT = 4.0
_MAX_RESPONSE = 4096
# A zone is found within a couple of label strips in practice; more than this is
# a sign the name is not served here at all.
_MAX_ZONE_CANDIDATES = 3


def encode_name(name: str) -> bytes:
    encoded = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def encode_empty_update(zone: str, txid: int) -> bytes:
    """An RFC 2136 UPDATE naming `zone` with no prerequisites and no changes."""
    flags = _OPCODE_UPDATE << 11
    # zocount=1, prcount=0, upcount=0, adcount=0
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    zone_section = encode_name(zone) + struct.pack("!HH", _TYPE_SOA, _CLASS_IN)
    return header + zone_section


def parse_rcode(data: bytes | None, txid: int) -> int | None:
    """Return the reply's rcode, or None when it is not a response to our query."""
    if not data or len(data) < 12:
        return None
    reply_id, flags = struct.unpack("!HH", data[:4])
    if reply_id != txid or not flags & _FLAG_QR:
        return None
    if (flags >> 11) & 0x0F != _OPCODE_UPDATE:
        return None
    return flags & 0x000F


def zone_candidates(hostname: str) -> list[str]:
    """Progressively shorter parent zones for a host name.

    The server tells us which one it is authoritative for (NOTAUTH for the rest),
    so guessing is cheap and self-correcting.
    """
    labels = [label for label in hostname.rstrip(".").lower().split(".") if label]
    candidates = []
    while len(labels) >= 2 and len(candidates) < _MAX_ZONE_CANDIDATES:
        candidates.append(".".join(labels))
        labels = labels[1:]
    return candidates


class DnsDynamicUpdatePlugin(PluginBase):
    id = "services.dns_dynamic_update"
    name = "Unauthenticated DNS Dynamic Update"
    description = (
        "Detect DNS servers that accept RFC 2136 dynamic updates without "
        "authentication, allowing record injection and name hijacking"
    )
    category = PluginCategory.services
    severity = Severity.high
    ports = [53]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not self._dns_port_open(host):
            return []

        hostname = self._zone_source(context, host)
        if not hostname:
            # Without a name there is no zone to name in the UPDATE, and
            # guessing zones at a bare resolver would be noise.
            return []

        for txid, zone in enumerate(zone_candidates(hostname), start=0x7000):
            rcode = await self._probe(host.ip, zone, txid)
            if rcode is None:
                continue
            if rcode == RCODE_NOERROR:
                return [self._build_finding(host.ip, zone)]
            if rcode in (RCODE_REFUSED, RCODE_NOTIMP):
                # Authoritative and correctly refusing us. Parent zones are a
                # different server's business.
                return []
        return []

    @staticmethod
    def _dns_port_open(host: "Host") -> bool:
        return any(
            port.number == 53 and port.state in ("open", "open|filtered")
            for port in host.ports
        )

    @staticmethod
    def _zone_source(context: "ScanContext", host: "Host") -> str | None:
        hostname = (getattr(host, "hostname", None) or "").strip().lower()
        if not hostname and context is not None:
            hostname = (context.original_hostname(host.ip) or "").strip().lower()
        hostname = hostname.removeprefix("*.")
        return hostname if hostname and "." in hostname else None

    async def _probe(self, ip: str, zone: str, txid: int) -> int | None:
        packet = encode_empty_update(zone, txid)
        loop = asyncio.get_running_loop()
        try:
            reply = await loop.run_in_executor(None, self._udp_exchange, ip, packet)
        except Exception as exc:
            logger.debug("dynamic-update probe failed on %s (%s): %s", ip, zone, exc)
            return None
        return parse_rcode(reply, txid)

    @staticmethod
    def _udp_exchange(ip: str, packet: bytes) -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(_UDP_TIMEOUT)
            sock.sendto(packet, (ip, 53))
            data, _ = sock.recvfrom(_MAX_RESPONSE)
            return data
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    def _build_finding(self, ip: str, zone: str) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title=f"Unauthenticated DNS Dynamic Update Accepted for {zone}",
            description=(
                f"The DNS server on {ip}:53 accepted an unauthenticated RFC 2136 "
                f"dynamic update for the zone {zone}. An attacker on this network can "
                "add records or overwrite existing ones without any credential.\n\n"
                "The consequences are not limited to the zone's own hosts. Adding a "
                "'wpad' record makes every browser that honours WPAD ask the attacker "
                "for its proxy configuration. Adding a wildcard record captures every "
                "name the zone does not already define. Overwriting an existing A "
                "record redirects that service's clients — including clients that will "
                "authenticate to whatever answers."
            ),
            evidence=(
                f"DNS UPDATE (opcode 5) for zone {zone} sent to {ip}:53 with an empty "
                "update section → rcode=NOERROR.\n"
                "An empty update section means the server had nothing to apply, so no "
                "record was created by this check. NOERROR is the server confirming it "
                "would have applied changes from this unauthenticated source; a server "
                "with a policy would have answered REFUSED."
            ),
            remediation=(
                "Require authenticated updates. BIND: replace 'allow-update { any; }' "
                "with 'update-policy' using TSIG keys, or remove dynamic updates "
                "entirely on static zones. Microsoft DNS: set the zone's dynamic "
                "update setting to 'Secure only', which requires Kerberos-authenticated "
                "updates. Where a DHCP server performs updates on clients' behalf, give "
                "it a TSIG key or a dedicated credential rather than opening the zone."
            ),
            references=[
                "https://datatracker.ietf.org/doc/html/rfc2136",
                "https://datatracker.ietf.org/doc/html/rfc3007",
                "https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/",
            ],
            port_number=53,
            protocol="udp",
            peer_review_command=(
                f"nsupdate <<< $'server {ip}\\nzone {zone}\\nsend\\n'   # empty update; NOERROR = accepted"
            ),
        )
