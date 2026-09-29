"""Read and parse a server's SSH_MSG_KEXINIT.

``paramiko.get_security_options()`` returns the *client's* preferences, not the
server's, so a check built on it reports our own configuration back at us. The
only authoritative source for what a server supports is the KEXINIT packet it
sends immediately after the version exchange, so we read that packet directly.

Nothing here authenticates or completes a key exchange: the connection is closed
after the server's first packet, before any credential could be offered.
"""
from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_MSG_KEXINIT = 20
_MAX_PACKET = 65536
_MAX_BANNER = 512
_CLIENT_IDENT = b"SSH-2.0-ScanR_probe\r\n"

# Name-lists in a KEXINIT, in wire order (RFC 4253 §7.1).
_NAME_LIST_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_c2s",
    "encryption_s2c",
    "mac_c2s",
    "mac_s2c",
    "compression_c2s",
    "compression_s2c",
    "languages_c2s",
    "languages_s2c",
)


@dataclass
class KexInit:
    """The algorithms a server advertised, plus its version banner."""

    banner: str = ""
    kex_algorithms: list[str] = field(default_factory=list)
    server_host_key_algorithms: list[str] = field(default_factory=list)
    encryption_c2s: list[str] = field(default_factory=list)
    encryption_s2c: list[str] = field(default_factory=list)
    mac_c2s: list[str] = field(default_factory=list)
    mac_s2c: list[str] = field(default_factory=list)
    compression_c2s: list[str] = field(default_factory=list)
    compression_s2c: list[str] = field(default_factory=list)
    languages_c2s: list[str] = field(default_factory=list)
    languages_s2c: list[str] = field(default_factory=list)

    def supports_kex(self, name: str) -> bool:
        return name in self.kex_algorithms


def parse_kexinit(payload: bytes, banner: str = "") -> KexInit | None:
    """Parse a KEXINIT payload (starting at the message-type byte).

    Returns None for anything that is not a well-formed KEXINIT — a truncated
    packet or a different message type is refused rather than parsed into
    misleading empty lists.
    """
    # msg_type(1) + cookie(16) + at least one empty name-list(4)
    if len(payload) < 21 or payload[0] != _MSG_KEXINIT:
        return None

    position = 17  # past the message type and the 16-byte cookie
    lists: dict[str, list[str]] = {}
    for name in _NAME_LIST_FIELDS:
        if position + 4 > len(payload):
            return None
        (length,) = struct.unpack(">I", payload[position:position + 4])
        position += 4
        if position + length > len(payload):
            return None
        raw = payload[position:position + length].decode("ascii", errors="ignore")
        lists[name] = [entry.strip() for entry in raw.split(",") if entry.strip()]
        position += length

    return KexInit(banner=banner, **lists)


def read_server_kexinit(ip: str, port: int, timeout: float = 5.0) -> KexInit | None:
    """Connect, read the version banner and the server's KEXINIT, then disconnect.

    Synchronous by design — callers run it in an executor, matching the other
    socket-level checks in this package.
    """
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        banner = b""
        while b"\n" not in banner and len(banner) < _MAX_BANNER:
            chunk = sock.recv(1)
            if not chunk:
                break
            banner += chunk
        if not banner.startswith(b"SSH-"):
            return None
        sock.sendall(_CLIENT_IDENT)

        raw_length = _recv_exactly(sock, 4)
        if raw_length is None:
            return None
        (packet_length,) = struct.unpack(">I", raw_length)
        if not 0 < packet_length <= _MAX_PACKET:
            return None
        body = _recv_exactly(sock, packet_length)
        if body is None or len(body) < 2:
            return None

        padding_length = body[0]
        if padding_length >= packet_length:
            return None
        payload = body[1:packet_length - padding_length]
        return parse_kexinit(payload, banner.decode("ascii", errors="replace").strip())
    except (OSError, struct.error) as exc:
        logger.debug("SSH KEXINIT read failed %s:%d: %s", ip, port, exc)
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exactly(sock: socket.socket, count: int) -> bytes | None:
    buffer = b""
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            return None
        buffer += chunk
    return buffer
