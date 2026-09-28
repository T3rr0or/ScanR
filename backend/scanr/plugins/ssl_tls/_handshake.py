"""TLS handshake feature probing.

``_tls_probe`` answers "will this server accept cipher suite X". This module
answers a different question: what does the server's *handshake* say about the
protections it implements — secure renegotiation, record compression, OCSP
stapling, session tickets.

Those answers live in the ServerHello's compression byte and extension list, and
in whether the server's first flight includes a CertificateStatus message. The
Python ``ssl`` module exposes almost none of it, so the ClientHello is assembled
by hand here too. The connection is dropped after the server's first flight:
nothing is decrypted, no application data is sent, and no renegotiation is ever
actually requested.
"""
from __future__ import annotations

import asyncio
import logging
import os
import struct
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

__all__ = [
    "COMPRESSION_DEFLATE",
    "EXT_RENEGOTIATION_INFO",
    "EXT_SESSION_TICKET",
    "EXT_STATUS_REQUEST",
    "EXT_SUPPORTED_VERSIONS",
    "HANDSHAKE_CERTIFICATE_STATUS",
    "ServerHello",
    "build_feature_hello",
    "parse_first_flight",
    "probe_handshake",
]

_RECORD_HANDSHAKE = 0x16
_RECORD_ALERT = 0x15
_RECORD_VERSION = 0x0301

_TLS10 = 0x0301
_TLS12 = 0x0303
_TLS13 = 0x0304

HANDSHAKE_SERVER_HELLO = 0x02
HANDSHAKE_CERTIFICATE = 0x0B
HANDSHAKE_CERTIFICATE_STATUS = 0x16
HANDSHAKE_SERVER_HELLO_DONE = 0x0E

EXT_SERVER_NAME = 0x0000
EXT_STATUS_REQUEST = 0x0005
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_SESSION_TICKET = 0x0023
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_RENEGOTIATION_INFO = 0xFF01

COMPRESSION_NULL = 0x00
COMPRESSION_DEFLATE = 0x01

_READ_LIMIT = 65536
_MAX_FLIGHT = 262144

# A broad, ordinary suite list. The point here is to complete a handshake the way
# any client would, not to test a specific suite, so anything a modern or a
# legacy server prefers is offered.
DEFAULT_SUITES: tuple[int, ...] = (
    0xC02F, 0xC030, 0xC02B, 0xC02C,   # ECDHE-RSA/ECDSA with AES-GCM
    0xC013, 0xC014, 0xC009, 0xC00A,   # ECDHE with AES-CBC
    0x009C, 0x009D,                    # RSA with AES-GCM
    0x002F, 0x0035, 0x003C,            # RSA with AES-CBC
    0x000A,                            # RSA with 3DES
    0xCCA8, 0xCCA9,                    # ECDHE with ChaCha20-Poly1305
)


@dataclass
class ServerHello:
    """What the server chose, and which handshake features it acknowledged."""

    version: int = 0
    cipher: int = 0
    compression: int = COMPRESSION_NULL
    session_id: bytes = b""
    extensions: dict[int, bytes] = field(default_factory=dict)
    handshake_types: set[int] = field(default_factory=set)

    @property
    def negotiated_version(self) -> int:
        """The real version, reading supported_versions where TLS 1.3 hides it.

        A TLS 1.3 server writes 0x0303 in the legacy_version field and puts the
        actual version in an extension, so the legacy field alone would report
        every TLS 1.3 server as TLS 1.2.
        """
        raw = self.extensions.get(EXT_SUPPORTED_VERSIONS)
        if raw and len(raw) >= 2:
            return int.from_bytes(raw[:2], "big")
        return self.version

    @property
    def is_tls13(self) -> bool:
        return self.negotiated_version >= _TLS13

    def version_name(self) -> str:
        return {
            _TLS13: "TLS 1.3",
            _TLS12: "TLS 1.2",
            0x0302: "TLS 1.1",
            _TLS10: "TLS 1.0",
            0x0300: "SSLv3",
        }.get(self.negotiated_version, f"0x{self.negotiated_version:04x}")

    def has_extension(self, ext_type: int) -> bool:
        return ext_type in self.extensions

    def stapled_ocsp(self) -> bool:
        """True when the server actually stapled a response, or promised one.

        TLS 1.2 answers a status_request by echoing the extension in the
        ServerHello and sending CertificateStatus; TLS 1.3 carries the response
        inside the Certificate message instead, where it is encrypted and
        therefore not visible to this probe.
        """
        return (
            HANDSHAKE_CERTIFICATE_STATUS in self.handshake_types
            or self.has_extension(EXT_STATUS_REQUEST)
        )


def _extension(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def _sni_extension(hostname: str) -> bytes:
    if not hostname:
        return b""
    try:
        host = hostname.encode("idna")
    except UnicodeError:
        return b""
    entry = struct.pack("!BH", 0x00, len(host)) + host
    return _extension(EXT_SERVER_NAME, struct.pack("!H", len(entry)) + entry)


def build_feature_hello(
    hostname: str = "",
    *,
    suites: tuple[int, ...] | list[int] = DEFAULT_SUITES,
    compression: tuple[int, ...] = (COMPRESSION_NULL, COMPRESSION_DEFLATE),
    request_ocsp: bool = True,
    request_ticket: bool = True,
    offer_renegotiation_info: bool = True,
    session_id: bytes = b"",
    ticket: bytes = b"",
) -> bytes:
    """A TLS 1.2 ClientHello that asks for every feature under test.

    Deliberately caps at TLS 1.2: the features measured here (renegotiation,
    record compression) do not exist in TLS 1.3, and a TLS 1.2 ClientHello is
    what a server must answer to be measurable at all.
    """
    body = struct.pack("!H", _TLS12)
    body += os.urandom(32)
    if len(session_id) > 32:
        raise ValueError("a TLS session id cannot exceed 32 bytes")
    body += bytes([len(session_id)]) + session_id

    suite_bytes = b"".join(struct.pack("!H", code) for code in suites)
    body += struct.pack("!H", len(suite_bytes)) + suite_bytes

    body += bytes([len(compression)]) + bytes(compression)

    extensions = _sni_extension(hostname)
    groups = struct.pack("!HHHH", 0x001D, 0x0017, 0x0018, 0x0019)
    extensions += _extension(EXT_SUPPORTED_GROUPS, struct.pack("!H", len(groups)) + groups)
    extensions += _extension(EXT_EC_POINT_FORMATS, b"\x01\x00")
    sig_algs = struct.pack("!HHHHHHHH", 0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203)
    extensions += _extension(EXT_SIGNATURE_ALGORITHMS, struct.pack("!H", len(sig_algs)) + sig_algs)
    if request_ocsp:
        # status_request: OCSP(1), empty responder id list, empty extensions.
        extensions += _extension(EXT_STATUS_REQUEST, b"\x01" + b"\x00\x00" + b"\x00\x00")
    if request_ticket:
        extensions += _extension(EXT_SESSION_TICKET, ticket)
    if offer_renegotiation_info:
        # Empty renegotiated_connection — the RFC 5746 signal for an initial
        # handshake. A compliant server echoes this extension back.
        extensions += _extension(EXT_RENEGOTIATION_INFO, b"\x00")
    body += struct.pack("!H", len(extensions)) + extensions

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", _RECORD_HANDSHAKE, _RECORD_VERSION, len(handshake)) + handshake


def _iter_handshake_messages(data: bytes):
    """Yield (type, body) for each handshake message across all TLS records.

    Records are reassembled before messages are split out, because a server is
    free to split one handshake message across records or pack several into one.
    """
    payload = b""
    offset = 0
    while offset + 5 <= len(data):
        content_type, _version, record_length = struct.unpack("!BHH", data[offset:offset + 5])
        offset += 5
        if record_length <= 0 or offset + record_length > len(data):
            break
        if content_type == _RECORD_ALERT:
            break
        if content_type == _RECORD_HANDSHAKE:
            payload += data[offset:offset + record_length]
        offset += record_length

    position = 0
    while position + 4 <= len(payload):
        msg_type = payload[position]
        msg_length = int.from_bytes(payload[position + 1:position + 4], "big")
        position += 4
        if position + msg_length > len(payload):
            # Truncated final message — everything complete has already been
            # yielded, so stop rather than guess at the remainder.
            break
        yield msg_type, payload[position:position + msg_length]
        position += msg_length


def _parse_extensions(raw: bytes) -> dict[int, bytes]:
    extensions: dict[int, bytes] = {}
    position = 0
    while position + 4 <= len(raw):
        ext_type, ext_length = struct.unpack("!HH", raw[position:position + 4])
        position += 4
        if position + ext_length > len(raw):
            break
        extensions[ext_type] = raw[position:position + ext_length]
        position += ext_length
    return extensions


def parse_first_flight(data: bytes | None) -> ServerHello | None:
    """Parse a server's first flight. None for anything that is not a ServerHello.

    Treating malformed or aborted handshakes as "no answer" keeps a hostile or
    broken server from being reported as missing a protection it was never asked
    about.
    """
    if not data or len(data) < 5:
        return None

    hello: ServerHello | None = None
    seen: set[int] = set()
    for msg_type, body in _iter_handshake_messages(data[:_MAX_FLIGHT]):
        seen.add(msg_type)
        if msg_type != HANDSHAKE_SERVER_HELLO or hello is not None:
            continue
        # version(2) + random(32) + session_id_len(1)
        if len(body) < 35:
            return None
        session_id_length = body[34]
        offset = 35 + session_id_length
        if len(body) < offset + 3:
            return None
        version = int.from_bytes(body[:2], "big")
        cipher = int.from_bytes(body[offset:offset + 2], "big")
        compression = body[offset + 2]
        offset += 3
        extensions: dict[int, bytes] = {}
        if len(body) >= offset + 2:
            ext_total = int.from_bytes(body[offset:offset + 2], "big")
            extensions = _parse_extensions(body[offset + 2:offset + 2 + ext_total])
        hello = ServerHello(
            version=version,
            cipher=cipher,
            compression=compression,
            session_id=body[35:35 + session_id_length],
            extensions=extensions,
        )

    if hello is None:
        return None
    hello.handshake_types = seen
    return hello


async def probe_handshake(
    ip: str, port: int, hello: bytes, *, timeout: float = 6.0
) -> bytes | None:
    """Send `hello` and read the server's reply. None on any connection failure."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(hello)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = b""
        deadline = asyncio.get_running_loop().time() + timeout
        # The first flight arrives as several records; keep reading until the
        # server finishes it or the deadline passes.
        while len(data) < _MAX_FLIGHT:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(_READ_LIMIT), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            data += chunk
            if _flight_complete(data):
                break
        return data or None
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        logger.debug("TLS handshake probe failed %s:%d: %s", ip, port, exc)
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass


def _flight_complete(data: bytes) -> bool:
    """True once ServerHelloDone arrived, or the server aborted with an alert."""
    for msg_type, _body in _iter_handshake_messages(data):
        if msg_type == HANDSHAKE_SERVER_HELLO_DONE:
            return True
    # An alert record means the handshake is over either way.
    offset = 0
    while offset + 5 <= len(data):
        content_type, _version, record_length = struct.unpack("!BHH", data[offset:offset + 5])
        if content_type == _RECORD_ALERT:
            return True
        offset += 5 + record_length
    return False
