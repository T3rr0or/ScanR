"""Open recursive DNS resolver detection (UDP/53).

A resolver that answers recursive queries for names it is not authoritative for,
from anywhere on the internet, is two problems at once. It is a reflector — a
small query returns a large answer to whatever source address the attacker
spoofs — and it is a cache an outsider can influence and snoop.

The check is a normal DNS client query, which is what makes it safe: we ask the
server to resolve a name it cannot be authoritative for and read the answer. A
resolver that is closed refuses or ignores it; one that is open answers with
``rcode=NOERROR`` and the recursion-available bit set.

Amplification is then *measured* rather than assumed: the same server is asked
for a large record type and the response/request byte ratio is reported. No
traffic is ever sent to a third party — every packet in this check goes to the
host under test and comes back to us.
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

# A name the target cannot be authoritative for. Resolving it requires
# recursion, which is precisely the behaviour under test. Deliberately a
# well-known, high-availability zone so a NOERROR is about the resolver's
# configuration rather than the name's existence.
_RECURSION_PROBE = "www.iana.org"
# A name whose ANY/DNSKEY answer is large, for measuring amplification.
_AMPLIFICATION_PROBE = "isc.org"

_QTYPE_A = 1
_QTYPE_DNSKEY = 48

_RCODE_NOERROR = 0
_FLAG_QR = 0x8000
_FLAG_RD = 0x0100
_FLAG_RA = 0x0080

# Below this the server is answering but is not a useful reflector.
_AMPLIFICATION_REPORT_THRESHOLD = 2.0
# ANY/DNSKEY answers of this size make the host a practical DDoS amplifier.
_AMPLIFICATION_HIGH = 10.0

_UDP_TIMEOUT = 4.0
_MAX_RESPONSE = 4096


def encode_query(name: str, qtype: int, txid: int, *, recursion: bool = True) -> bytes:
    """Build a minimal DNS query packet (RFC 1035), EDNS0-enabled."""
    flags = _FLAG_RD if recursion else 0
    # qdcount=1, ancount=0, nscount=0, arcount=1 (the OPT record below)
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 1)

    qname = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna")
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)  # class IN

    # OPT pseudo-RR advertising a 4096-byte receive buffer. Without it the
    # server truncates at 512 bytes and the amplification measurement would
    # understate every server that supports EDNS0 — which is all of them.
    opt = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
    return header + question + opt


def parse_response(data: bytes | None, txid: int) -> tuple[int, bool, int] | None:
    """Return (rcode, recursion_available, answer_count), or None if not our reply.

    Anything that is not a well-formed response to the exact transaction we sent
    is refused. A resolver is only reported on evidence we can tie to our own
    query.
    """
    if not data or len(data) < 12:
        return None
    reply_id, flags, _qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
    if reply_id != txid:
        return None
    if not flags & _FLAG_QR:  # not a response
        return None
    return flags & 0x000F, bool(flags & _FLAG_RA), ancount


class OpenResolverPlugin(PluginBase):
    id = "network.open_resolver"
    name = "Open Recursive DNS Resolver"
    description = (
        "Detect DNS servers that answer recursive queries from any source, "
        "making them DDoS reflectors and cache-poisoning targets"
    )
    category = PluginCategory.network
    severity = Severity.medium
    ports = [53]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not self._dns_port_open(host):
            return []

        txid = 0x1337
        recursion = await self._query(host.ip, _RECURSION_PROBE, _QTYPE_A, txid)
        if recursion is None:
            return []
        parsed = parse_response(recursion[0], txid)
        if parsed is None:
            return []
        rcode, recursion_available, answers = parsed

        # A REFUSED/SERVFAIL, or an empty NOERROR, is a correctly closed
        # resolver. Only a real answer proves recursion is being performed for
        # an arbitrary source.
        if rcode != _RCODE_NOERROR or answers < 1:
            return []

        amplification = await self._measure_amplification(host.ip)
        return [self._build_finding(host.ip, recursion_available, answers, amplification)]

    @staticmethod
    def _dns_port_open(host: "Host") -> bool:
        for port in host.ports:
            if port.number != 53:
                continue
            # nmap rarely distinguishes open from filtered on UDP, so both are
            # probed and our own reply decides.
            if port.state in ("open", "open|filtered"):
                return True
        return False

    async def _measure_amplification(self, ip: str) -> tuple[int, int, float] | None:
        """Return (request_bytes, response_bytes, factor) for a DNSKEY query."""
        txid = 0x4242
        result = await self._query(ip, _AMPLIFICATION_PROBE, _QTYPE_DNSKEY, txid)
        if result is None:
            return None
        data, request_size = result
        parsed = parse_response(data, txid)
        if parsed is None or not data:
            return None
        factor = round(len(data) / request_size, 1) if request_size else 0.0
        return request_size, len(data), factor

    async def _query(
        self, ip: str, name: str, qtype: int, txid: int
    ) -> tuple[bytes | None, int] | None:
        """Send one UDP query; returns (reply_or_None, request_size)."""
        packet = encode_query(name, qtype, txid)
        loop = asyncio.get_running_loop()
        try:
            reply = await loop.run_in_executor(None, self._udp_exchange, ip, packet)
        except Exception as exc:
            logger.debug("DNS probe failed for %s: %s", ip, exc)
            return None
        return reply, len(packet)

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

    def _build_finding(
        self,
        ip: str,
        recursion_available: bool,
        answers: int,
        amplification: tuple[int, int, float] | None,
    ) -> FindingData:
        severity = Severity.medium
        evidence = [
            f"Recursive query for {_RECURSION_PROBE} (A) to {ip}:53 → "
            f"rcode=NOERROR, {answers} answer record(s), RA={'set' if recursion_available else 'clear'}",
            f"{ip} is not authoritative for {_RECURSION_PROBE}, so answering it "
            "means recursion was performed on our behalf.",
        ]

        amplification_note = ""
        if amplification:
            request_size, response_size, factor = amplification
            evidence.append(
                f"DNSKEY query for {_AMPLIFICATION_PROBE}: {request_size}-byte request → "
                f"{response_size}-byte response (~{factor}x amplification)"
            )
            if factor >= _AMPLIFICATION_HIGH:
                severity = Severity.high
                amplification_note = (
                    f" Measured amplification is ~{factor}x, which makes this host a "
                    "practical DDoS reflector: an attacker spoofing a victim's source "
                    "address turns a small query into a large unsolicited response."
                )
            elif factor >= _AMPLIFICATION_REPORT_THRESHOLD:
                amplification_note = (
                    f" Measured amplification is ~{factor}x."
                )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="Open Recursive DNS Resolver",
            description=(
                f"The DNS server on {ip}:53/udp performs recursive resolution for "
                "clients outside its own network. Two consequences follow. It can be "
                "used as a reflector in amplification DDoS attacks against third "
                "parties, which is traffic attributed to this host's owner. And its "
                "cache is reachable by outsiders, exposing it to cache-poisoning and "
                "cache-snooping — an attacker can learn which names this "
                "organisation's users have been resolving."
                + amplification_note
            ),
            evidence="\n".join(evidence),
            remediation=(
                "Restrict recursion to internal client ranges. BIND: "
                "'allow-recursion { localnets; };' and 'recursion no;' on "
                "authoritative-only servers. Unbound: set 'access-control' to the "
                "internal ranges only. Windows DNS: clear 'Enable recursion' on "
                "servers that only host zones. Where a resolver must face the "
                "internet, enable response rate limiting (RRL) to blunt its use as "
                "a reflector."
            ),
            references=[
                "https://www.cisa.gov/news-events/alerts/2013/01/17/alert-ta13-088a-dns-amplification-attacks",
                "https://openresolverproject.org/",
                "https://kb.isc.org/docs/aa-00269",
            ],
            port_number=53,
            protocol="udp",
            peer_review_command=f"dig +short @{ip} {_RECURSION_PROBE} A",
        )
