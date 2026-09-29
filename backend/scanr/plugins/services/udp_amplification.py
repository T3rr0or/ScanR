"""UDP reflection/amplification vector detection.

An amplifier is a service that answers a small UDP request with a much larger
reply. Because UDP source addresses are trivially forged, an attacker points the
reply at a victim and the bandwidth bill — and the abuse complaint — lands on
whoever runs the amplifier.

ScanR already checks the two most famous vectors (NTP monlist, memcached). This
covers the rest of the set that actually shows up on perimeter scans: CLDAP,
portmap/rpcbind, RIPv1, SSDP, CharGEN and QOTD.

Each vector is measured, not assumed. The plugin sends one request, validates
that the reply is really that protocol answering our own request, and reports the
observed response/request byte ratio. Nothing is spoofed: every packet is sent
from this scanner to the target and every reply comes back to this scanner, so no
third party receives traffic as a result of the check.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_UDP_TIMEOUT = 4.0
_MAX_RESPONSE = 65535

# Below this ratio the service answers but is not a useful reflector, so
# reporting it would be noise — the exposure of the service itself is another
# plugin's job.
_REPORT_THRESHOLD = 2.0
# At or above this, the host is a practical DDoS amplifier.
_HIGH_FACTOR = 10.0

# ── CLDAP (connectionless LDAP, UDP/389) ─────────────────────────────────────
# A rootDSE searchRequest: base "", scope base, filter (objectClass=present),
# no attribute restriction — so the DC returns its entire rootDSE.
#   30 25            SEQUENCE, 37 bytes
#   02 01 01         messageID 1
#   63 20            [APPLICATION 3] searchRequest, 32 bytes
#   04 00            baseObject ""
#   0a 01 00         scope baseObject
#   0a 01 00         derefAliases neverDerefAliases
#   02 01 00         sizeLimit 0
#   02 01 00         timeLimit 0
#   01 01 00         typesOnly FALSE
#   87 0b "objectClass"   present filter
#   30 00            attributes: none (= all)
_CLDAP_REQUEST = bytes.fromhex(
    "3025"                      # SEQUENCE, 37 bytes
    "020101"                    # messageID 1
    "6320"                      # searchRequest, 32 bytes
    "0400"                      # baseObject ""
    "0a0100"                    # scope baseObject
    "0a0100"                    # derefAliases neverDerefAliases
    "020100"                    # sizeLimit 0
    "020100"                    # timeLimit 0
    "010100"                    # typesOnly FALSE
    "870b6f626a656374436c617373"  # present filter: "objectClass"
    "3000"                      # attributes: none requested (= all)
)

# ── RIPv1 (UDP/520) ──────────────────────────────────────────────────────────
# command=1 (request), version=1, then a single RTE with AF=0 and metric=16,
# which RFC 1058 §3.4.1 defines as "send me your whole routing table".
_RIPV1_REQUEST = (
    struct.pack("!BBH", 1, 1, 0)
    + struct.pack("!HH", 0, 0)
    + b"\x00" * 4 * 3
    + struct.pack("!I", 16)
)

# ── SSDP (UDP/1900) ──────────────────────────────────────────────────────────
_SSDP_REQUEST = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 1\r\n"
    b"ST: ssdp:all\r\n"
    b"\r\n"
)

# ── portmap / rpcbind (UDP/111) ──────────────────────────────────────────────
# PMAPPROC_DUMP (program 100000, version 2, procedure 4) returns every
# registered RPC program — a small call for a long list.
_PORTMAP_XID = 0x5343414E
_PORTMAP_REQUEST = (
    struct.pack("!IIIIII", _PORTMAP_XID, 0, 2, 100000, 2, 4)
    + struct.pack("!II", 0, 0)   # null credentials
    + struct.pack("!II", 0, 0)   # null verifier
)

# CharGEN and QOTD answer literally anything.
_TRIVIAL_REQUEST = b"\x0d\x0a"


def _valid_cldap(data: bytes) -> bool:
    """A BER SEQUENCE carrying an LDAP searchResEntry or searchResDone."""
    if len(data) < 7 or data[0] != 0x30:
        return False
    return b"\x64" in data[:16] or b"\x65" in data or b"supportedCapabilities" in data


def _valid_ripv1(data: bytes) -> bool:
    """command=2 (response), version=1, and a whole number of 20-byte RTEs."""
    if len(data) < 24 or data[0] != 2 or data[1] != 1:
        return False
    return (len(data) - 4) % 20 == 0


def _valid_ssdp(data: bytes) -> bool:
    return data[:4] == b"HTTP" and b"200" in data[:32]


def _valid_portmap(data: bytes) -> bool:
    """Our XID back, msg_type=REPLY(1), reply_stat=MSG_ACCEPTED(0)."""
    if len(data) < 24:
        return False
    xid, msg_type, reply_stat = struct.unpack("!III", data[:12])
    return xid == _PORTMAP_XID and msg_type == 1 and reply_stat == 0


def _valid_text_stream(data: bytes) -> bool:
    """CharGEN/QOTD emit printable text; anything binary is a different service."""
    if len(data) < 8:
        return False
    printable = sum(1 for byte in data if 0x20 <= byte <= 0x7E or byte in (0x09, 0x0A, 0x0D))
    return printable / len(data) > 0.9


@dataclass(frozen=True)
class Vector:
    port: int
    protocol: str
    request: bytes
    validate: Callable[[bytes], bool]
    remediation: str
    reference: str
    # Several vectors answer a single request with many packets; read that many.
    reads: int = 1


VECTORS: tuple[Vector, ...] = (
    Vector(
        port=389,
        protocol="CLDAP",
        request=_CLDAP_REQUEST,
        validate=_valid_cldap,
        remediation=(
            "Block UDP/389 at the perimeter — CLDAP has no legitimate internet-facing "
            "use. Domain controllers should only answer CLDAP from internal client "
            "ranges."
        ),
        reference="https://www.akamai.com/blog/security/cldap-reflection-ddos",
    ),
    Vector(
        port=111,
        protocol="portmap/rpcbind",
        request=_PORTMAP_REQUEST,
        validate=_valid_portmap,
        remediation=(
            "Block UDP/111 at the perimeter. On Linux, restrict rpcbind with "
            "/etc/hosts.allow or run NFSv4 only, which does not need portmap."
        ),
        reference="https://www.cisa.gov/news-events/alerts/2015/08/18/udp-based-amplification-attacks",
    ),
    Vector(
        port=520,
        protocol="RIPv1",
        request=_RIPV1_REQUEST,
        validate=_valid_ripv1,
        remediation=(
            "Disable RIPv1 — it has no authentication at all. Move to RIPv2 with "
            "MD5 authentication, or preferably OSPF/BGP, and never expose the "
            "routing protocol to untrusted networks."
        ),
        reference="https://www.cisa.gov/news-events/alerts/2015/08/18/udp-based-amplification-attacks",
    ),
    Vector(
        port=1900,
        protocol="SSDP",
        request=_SSDP_REQUEST,
        validate=_valid_ssdp,
        remediation=(
            "Block UDP/1900 inbound at the perimeter and disable UPnP on any device "
            "that does not need it. SSDP should never be reachable from outside the "
            "local segment."
        ),
        reference="https://www.cisa.gov/news-events/alerts/TA14-013A",
        reads=3,
    ),
    Vector(
        port=19,
        protocol="CharGEN",
        request=_TRIVIAL_REQUEST,
        validate=_valid_text_stream,
        remediation=(
            "Disable the chargen service. It is a 1980s debugging tool with no modern "
            "use: 'disable = yes' in /etc/xinetd.d/chargen-udp, or remove the "
            "Simple TCP/IP Services Windows feature."
        ),
        reference="https://www.cisa.gov/news-events/alerts/2015/08/18/udp-based-amplification-attacks",
    ),
    Vector(
        port=17,
        protocol="QOTD",
        request=_TRIVIAL_REQUEST,
        validate=_valid_text_stream,
        remediation=(
            "Disable the qotd service ('disable = yes' in /etc/xinetd.d/daytime-udp "
            "and qotd, or remove Simple TCP/IP Services on Windows)."
        ),
        reference="https://www.cisa.gov/news-events/alerts/2015/08/18/udp-based-amplification-attacks",
    ),
)

_VECTORS_BY_PORT = {vector.port: vector for vector in VECTORS}


def amplification_factor(request_size: int, response_size: int) -> float:
    if request_size <= 0:
        return 0.0
    return round(response_size / request_size, 1)


def severity_for(factor: float) -> Severity:
    return Severity.high if factor >= _HIGH_FACTOR else Severity.medium


class UdpAmplificationPlugin(PluginBase):
    id = "services.udp_amplification"
    name = "UDP Reflection/Amplification Vector"
    description = (
        "Measure UDP amplification on CLDAP, portmap, RIPv1, SSDP, CharGEN and "
        "QOTD — services abusable as spoofed-source DDoS reflectors"
    )
    category = PluginCategory.services
    severity = Severity.medium
    ports = sorted(_VECTORS_BY_PORT)

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            vector = _VECTORS_BY_PORT.get(port.number)
            if vector is None:
                continue
            # nmap usually cannot separate open from filtered on UDP, so both
            # are probed and the reply decides.
            if port.state not in ("open", "open|filtered"):
                continue
            if getattr(port, "protocol", "udp") not in (None, "", "udp"):
                continue
            finding = await self._measure(host.ip, vector)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _measure(self, ip: str, vector: Vector) -> FindingData | None:
        try:
            response_size = await self._probe(ip, vector)
        except Exception as exc:
            logger.debug("%s probe failed on %s: %s", vector.protocol, ip, exc)
            return None
        if not response_size:
            return None

        request_size = len(vector.request)
        factor = amplification_factor(request_size, response_size)
        if factor < _REPORT_THRESHOLD:
            return None
        return self._build_finding(ip, vector, request_size, response_size, factor)

    async def _probe(self, ip: str, vector: Vector) -> int:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._udp_exchange, ip, vector)

    @staticmethod
    def _udp_exchange(ip: str, vector: Vector) -> int:
        """Total validated response bytes, or 0 when nothing recognisable replied."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        total = 0
        try:
            sock.settimeout(_UDP_TIMEOUT)
            sock.sendto(vector.request, (ip, vector.port))
            for _ in range(vector.reads):
                try:
                    data, _ = sock.recvfrom(_MAX_RESPONSE)
                except (socket.timeout, OSError):
                    break
                if not data:
                    break
                # Only the first packet is authenticated as the right protocol;
                # subsequent packets of the same burst are counted as volume.
                if total == 0 and not vector.validate(data):
                    return 0
                total += len(data)
        finally:
            sock.close()
        return total

    def _build_finding(
        self, ip: str, vector: Vector, request_size: int, response_size: int, factor: float
    ) -> FindingData:
        severity = severity_for(factor)
        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=f"{vector.protocol} UDP Amplification Vector (~{factor}x)",
            description=(
                f"The {vector.protocol} service on {ip}:{vector.port}/udp answers a "
                f"{request_size}-byte request with {response_size} bytes — roughly "
                f"{factor}x amplification. UDP source addresses are not validated, so "
                "an attacker can send this request with a victim's address forged as "
                "the source and have this host deliver the amplified reply to that "
                "victim. The resulting traffic originates from this host and is "
                "attributed to its owner."
            ),
            evidence=(
                f"Sent {request_size} bytes to {ip}:{vector.port}/udp "
                f"({vector.protocol} request)\n"
                f"Received {response_size} bytes of validated {vector.protocol} "
                f"response\nAmplification factor: ~{factor}x"
            ),
            remediation=vector.remediation,
            references=[vector.reference],
            port_number=vector.port,
            protocol="udp",
        )
