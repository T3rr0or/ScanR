"""Raw TLS cipher-suite probing.

The probe exists because Python's ssl module cannot offer RC4/DES/3DES/EXPORT on
a modern OpenSSL, so a check built on it can never detect them. These tests pin
both the wire format we send and — against real TLS servers — that support is
reported only when the server genuinely accepts the suite.
"""
import datetime
import os
import socket
import ssl
import struct
import tempfile
import threading

import pytest

from scanr.plugins.ssl_tls._tls_probe import (
    SUITE_GROUPS,
    build_client_hello,
    parse_server_hello,
    probe_cipher_suites,
)


# ── wire format ──────────────────────────────────────────────────────────────

def test_client_hello_is_a_well_formed_handshake_record():
    hello = build_client_hello([0x002F, 0x0035], "example.test")
    content_type, version, length = struct.unpack("!BHH", hello[:5])
    assert content_type == 0x16          # handshake
    assert length == len(hello) - 5      # record length covers the body exactly
    assert hello[5] == 0x01              # ClientHello
    assert int.from_bytes(hello[6:9], "big") == len(hello) - 9


def test_client_hello_offers_exactly_the_requested_suites():
    hello = build_client_hello([0x000A, 0xC012])
    # version(2)+random(32)+session_id_len(1) after the 9-byte record+handshake header
    offset = 9 + 2 + 32 + 1
    suites_len = struct.unpack("!H", hello[offset:offset + 2])[0]
    offered = {
        struct.unpack("!H", hello[offset + 2 + i:offset + 4 + i])[0]
        for i in range(0, suites_len, 2)
    }
    assert offered == {0x000A, 0xC012}


def test_sni_is_included_only_when_a_hostname_is_given():
    assert b"example.test" in build_client_hello([0x002F], "example.test")
    assert b"example.test" not in build_client_hello([0x002F], "")


# ── response parsing ─────────────────────────────────────────────────────────

def _server_hello(cipher: int, session_id: bytes = b"") -> bytes:
    body = struct.pack("!H", 0x0303) + b"\x00" * 32
    body += bytes([len(session_id)]) + session_id
    body += struct.pack("!H", cipher) + b"\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 0x16, 0x0303, len(handshake)) + handshake


def test_parses_the_selected_suite():
    assert parse_server_hello(_server_hello(0x000A)) == 0x000A


def test_parses_around_a_session_id():
    assert parse_server_hello(_server_hello(0xC012, os.urandom(32))) == 0xC012


def test_alert_is_refusal():
    alert = struct.pack("!BHH", 0x15, 0x0303, 2) + b"\x02\x28"  # handshake_failure
    assert parse_server_hello(alert) is None


@pytest.mark.parametrize("data", [
    b"",
    b"\x16\x03",                                   # truncated record header
    struct.pack("!BHH", 0x16, 0x0303, 4) + b"\x01\x00\x00\x00",  # not a ServerHello
    struct.pack("!BHH", 0x17, 0x0303, 0),          # application data
])
def test_malformed_input_is_refusal_not_a_crash(data):
    """Anything unparseable must read as 'not supported', never as support."""
    assert parse_server_hello(data) is None


# ── against real TLS servers ─────────────────────────────────────────────────

def _self_signed() -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    directory = tempfile.mkdtemp()
    crt = os.path.join(directory, "c.pem")
    keyfile = os.path.join(directory, "k.pem")
    with open(crt, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return crt, keyfile


def _tls_server(cipher_spec: str):
    """Start a TLS server restricted to `cipher_spec`; returns (socket, port)."""
    crt, key = _self_signed()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(crt, key)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(cipher_spec)

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)

    def serve():
        while True:
            try:
                client, _ = server.accept()
            except OSError:
                return
            try:
                context.wrap_socket(client, server_side=True).close()
            except Exception:
                try:
                    client.close()
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return server, server.getsockname()[1]


@pytest.mark.asyncio
async def test_reports_support_only_when_the_server_accepts_it():
    permissive, p_port = _tls_server("kRSA:@SECLEVEL=0")
    hardened, h_port = _tls_server("ECDHE:@SECLEVEL=2")
    suites = SUITE_GROUPS["static RSA key exchange"]
    try:
        accepted = await probe_cipher_suites("127.0.0.1", p_port, suites, hostname="localhost")
        refused = await probe_cipher_suites("127.0.0.1", h_port, suites, hostname="localhost")
    finally:
        permissive.close()
        hardened.close()

    assert accepted is not None, "server offering static RSA must be reported"
    assert accepted.code in {s.code for s in suites}
    assert refused is None, "PFS-only server must not be reported"


@pytest.mark.asyncio
async def test_a_closed_port_is_not_reported_as_supporting_anything():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listening now
    result = await probe_cipher_suites(
        "127.0.0.1", port, SUITE_GROUPS["RC4"], timeout=2.0
    )
    assert result is None


@pytest.mark.asyncio
async def test_a_non_tls_service_is_not_reported_as_supporting_anything():
    """A plain TCP service must not be mistaken for a vulnerable TLS server."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    port = server.getsockname()[1]

    def serve():
        try:
            client, _ = server.accept()
        except OSError:
            return
        try:
            client.recv(4096)
            client.sendall(b"220 plain-text service ready\r\n")
        finally:
            client.close()

    threading.Thread(target=serve, daemon=True).start()
    try:
        result = await probe_cipher_suites(
            "127.0.0.1", port, SUITE_GROUPS["RC4"], timeout=3.0
        )
    finally:
        server.close()
    assert result is None


def test_every_group_is_non_empty_and_uniquely_coded():
    seen: dict[int, str] = {}
    for group, suites in SUITE_GROUPS.items():
        assert suites, f"{group} must list suites"
        for suite in suites:
            assert 0 <= suite.code <= 0xFFFF
            assert suite.code not in seen, (
                f"0x{suite.code:04x} in both {seen.get(suite.code)} and {group}"
            )
            seen[suite.code] = group
