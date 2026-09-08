"""Raw TLS cipher-suite probing.

Python's `ssl` module can only ask a server for suites the local OpenSSL is
willing to offer, and OpenSSL 3.x ships with RC4, DES, 3DES and the EXPORT
grades *compiled out*. A check built on `ssl` therefore cannot detect the very
weaknesses it is looking for: the handshake fails on our side, and the server's
support goes unreported.

So the ClientHello is assembled by hand. We offer exactly the suites under test
and read the server's reply: a ServerHello naming one of them proves support, an
alert proves refusal. No third-party dependency, and nothing here decrypts or
sends application data — the connection is dropped after the server's first
flight.
"""
from __future__ import annotations

import asyncio
import os
import struct

__all__ = ["CipherSuite", "probe_cipher_suites", "SUITE_GROUPS"]

_RECORD_HANDSHAKE = 0x16
_RECORD_ALERT = 0x15
_HANDSHAKE_SERVER_HELLO = 0x02

_TLS12 = 0x0303
# Announced in the record layer only; a permissive value keeps ancient servers
# from dropping the record before they read the ClientHello inside it.
_RECORD_VERSION = 0x0301

_READ_LIMIT = 16384


class CipherSuite:
    """A TLS cipher suite under test."""

    __slots__ = ("code", "name", "note")

    def __init__(self, code: int, name: str, note: str = ""):
        self.code = code
        self.name = name
        self.note = note

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"CipherSuite(0x{self.code:04x}, {self.name!r})"


# Grouped by the weakness they demonstrate. Codes are from the IANA TLS registry.
SUITE_GROUPS: dict[str, list[CipherSuite]] = {
    "NULL encryption": [
        CipherSuite(0x0001, "TLS_RSA_WITH_NULL_MD5"),
        CipherSuite(0x0002, "TLS_RSA_WITH_NULL_SHA"),
        CipherSuite(0x003B, "TLS_RSA_WITH_NULL_SHA256"),
        CipherSuite(0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
    ],
    "anonymous key exchange": [
        CipherSuite(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"),
        CipherSuite(0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"),
        CipherSuite(0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"),
        CipherSuite(0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"),
    ],
    "EXPORT grade": [
        CipherSuite(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
        CipherSuite(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
        CipherSuite(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
        CipherSuite(0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
        CipherSuite(0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"),
        CipherSuite(0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"),
    ],
    "RC4": [
        CipherSuite(0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
        CipherSuite(0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
        CipherSuite(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
        CipherSuite(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
    ],
    "single DES": [
        CipherSuite(0x0009, "TLS_RSA_WITH_DES_CBC_SHA"),
        CipherSuite(0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
    ],
    "64-bit block cipher (3DES)": [
        CipherSuite(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
        CipherSuite(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
        CipherSuite(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
        CipherSuite(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    ],
    "static RSA key exchange": [
        CipherSuite(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"),
        CipherSuite(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
        CipherSuite(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
        CipherSuite(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
        CipherSuite(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    ],
}

_ALL_BY_CODE: dict[int, CipherSuite] = {
    suite.code: suite for suites in SUITE_GROUPS.values() for suite in suites
}


def _extension(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def _sni_extension(hostname: str) -> bytes:
    host = hostname.encode("idna") if hostname else b""
    if not host:
        return b""
    entry = struct.pack("!BH", 0x00, len(host)) + host
    return _extension(0x0000, struct.pack("!H", len(entry)) + entry)


def build_client_hello(suites: list[int], hostname: str = "") -> bytes:
    """Assemble a TLS 1.2 ClientHello offering exactly `suites`."""
    body = struct.pack("!H", _TLS12)
    body += os.urandom(32)          # client random
    body += b"\x00"                 # no session id

    suite_bytes = b"".join(struct.pack("!H", code) for code in suites)
    body += struct.pack("!H", len(suite_bytes)) + suite_bytes
    body += b"\x01\x00"             # one compression method: null

    extensions = b""
    extensions += _sni_extension(hostname)
    # Groups and point formats, so ECDHE suites are actually negotiable.
    groups = struct.pack("!HHHH", 0x001D, 0x0017, 0x0018, 0x0019)
    extensions += _extension(0x000A, struct.pack("!H", len(groups)) + groups)
    extensions += _extension(0x000B, b"\x01\x00")
    # signature_algorithms is mandatory for TLS 1.2 negotiation.
    sig_algs = struct.pack(
        "!HHHHHH", 0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0201
    )
    extensions += _extension(0x000D, struct.pack("!H", len(sig_algs)) + sig_algs)
    body += struct.pack("!H", len(extensions)) + extensions

    handshake = struct.pack("!B", 0x01) + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", _RECORD_HANDSHAKE, _RECORD_VERSION, len(handshake)) + handshake


def parse_server_hello(data: bytes) -> int | None:
    """Return the cipher suite the server selected, or None if it refused.

    None covers every non-acceptance: an alert, a truncated reply, or anything
    that is not a well-formed ServerHello. Treating malformed input as refusal
    keeps a hostile or broken server from being reported as vulnerable.
    """
    if len(data) < 5:
        return None
    content_type, _version, record_len = struct.unpack("!BHH", data[:5])
    if content_type == _RECORD_ALERT:
        return None
    if content_type != _RECORD_HANDSHAKE:
        return None

    record = data[5:5 + record_len]
    if len(record) < 4 or record[0] != _HANDSHAKE_SERVER_HELLO:
        return None
    hello_len = int.from_bytes(record[1:4], "big")
    hello = record[4:4 + hello_len]
    # version(2) + random(32) + session_id_len(1)
    if len(hello) < 35:
        return None
    session_id_len = hello[34]
    offset = 35 + session_id_len
    if len(hello) < offset + 2:
        return None
    return struct.unpack("!H", hello[offset:offset + 2])[0]


async def probe_cipher_suites(
    ip: str,
    port: int,
    suites: list[CipherSuite],
    *,
    hostname: str = "",
    timeout: float = 6.0,
) -> CipherSuite | None:
    """Offer `suites` to the server; return the one it chose, or None.

    A returned suite is proof the server accepts it: the server picked it out of
    a ClientHello that offered nothing else.
    """
    if not suites:
        return None
    hello = build_client_hello([s.code for s in suites], hostname)
    offered = {s.code for s in suites}

    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(hello)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(_READ_LIMIT), timeout=timeout)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass

    chosen = parse_server_hello(data)
    if chosen is None:
        return None
    # A server that answers with something we never offered is misbehaving;
    # do not credit it as support for a suite under test.
    if chosen not in offered:
        return None
    return _ALL_BY_CODE.get(chosen) or CipherSuite(chosen, f"0x{chosen:04x}")
