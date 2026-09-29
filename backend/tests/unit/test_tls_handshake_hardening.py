"""TLS handshake hardening: renegotiation, compression, OCSP stapling.

Pins the ServerHello/first-flight parser and the three assessments, including the
TLS 1.3 carve-outs where the protections do not apply.
"""
from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from scanr.plugins.ssl_tls._handshake import (
    COMPRESSION_DEFLATE,
    COMPRESSION_NULL,
    EXT_RENEGOTIATION_INFO,
    EXT_STATUS_REQUEST,
    EXT_SUPPORTED_VERSIONS,
    HANDSHAKE_CERTIFICATE_STATUS,
    ServerHello,
    build_feature_hello,
    parse_first_flight,
)
from scanr.plugins.ssl_tls.handshake_hardening import (
    HandshakeHardeningPlugin,
    compression_enabled,
    insecure_renegotiation,
)


def _server_hello_record(version=0x0303, cipher=0xC02F, compression=0, extensions=b"",
                         handshake_type=0x02):
    body = struct.pack("!H", version) + b"\x00" * 32 + b"\x00"   # version+random+sid_len
    body += struct.pack("!H", cipher) + bytes([compression])
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 0x16, 0x0303, len(handshake)) + handshake


def _ext(ext_type, body=b""):
    return struct.pack("!HH", ext_type, len(body)) + body


def _port(number=443, state="open", service=None):
    return SimpleNamespace(number=number, state=state, service=service)


def _host(ports, ip="192.0.2.50"):
    return SimpleNamespace(ip=ip, hostname="tls.example", ports=ports)


# ── parsing ──────────────────────────────────────────────────────────────────

def test_parses_cipher_and_compression():
    hello = parse_first_flight(_server_hello_record(cipher=0x009C, compression=1))
    assert hello.cipher == 0x009C
    assert hello.compression == 1


def test_tls13_version_read_from_extension_not_legacy_field():
    ext = _ext(EXT_SUPPORTED_VERSIONS, struct.pack("!H", 0x0304))
    hello = parse_first_flight(_server_hello_record(version=0x0303, extensions=ext))
    assert hello.is_tls13


def test_non_serverhello_is_rejected():
    assert parse_first_flight(_server_hello_record(handshake_type=0x0B)) is None
    assert parse_first_flight(b"") is None


# ── assessments ──────────────────────────────────────────────────────────────

def test_renegotiation_missing_on_tls12_is_insecure():
    assert insecure_renegotiation(ServerHello(version=0x0303, extensions={}))


def test_renegotiation_present_is_ok():
    hello = ServerHello(version=0x0303, extensions={EXT_RENEGOTIATION_INFO: b"\x00"})
    assert not insecure_renegotiation(hello)


def test_tls13_without_reneg_extension_is_not_flagged():
    hello = ServerHello(extensions={EXT_SUPPORTED_VERSIONS: b"\x03\x04"})
    assert hello.is_tls13
    assert not insecure_renegotiation(hello)


def test_compression_detection():
    assert compression_enabled(ServerHello(compression=COMPRESSION_DEFLATE))
    assert not compression_enabled(ServerHello(compression=COMPRESSION_NULL))


def test_ocsp_stapled_when_certificate_status_present():
    hello = ServerHello(handshake_types={HANDSHAKE_CERTIFICATE_STATUS})
    assert hello.stapled_ocsp()
    hello2 = ServerHello(extensions={EXT_STATUS_REQUEST: b""})
    assert hello2.stapled_ocsp()
    assert not ServerHello().stapled_ocsp()


# ── ClientHello construction ─────────────────────────────────────────────────

def test_feature_hello_offers_compression_and_reneg_and_status():
    hello = build_feature_hello("tls.example")
    assert hello[0] == 0x16            # handshake record
    # DEFLATE offered so a compressing server will select it
    assert bytes([COMPRESSION_NULL, COMPRESSION_DEFLATE]) in hello


# ── plugin behaviour ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_all_three_gaps_reported(monkeypatch):
    async def fake_hello(ip, port, hostname):
        return ServerHello(version=0x0303, compression=COMPRESSION_DEFLATE, extensions={})
    monkeypatch.setattr(HandshakeHardeningPlugin, "_server_hello", staticmethod(fake_hello))
    findings = await HandshakeHardeningPlugin().check(None, _host([_port()]))
    titles = {f.title for f in findings}
    assert any("Renegotiation" in t for t in titles)
    assert any("Compression" in t for t in titles)
    assert any("OCSP" in t for t in titles)


@pytest.mark.asyncio
async def test_hardened_tls13_server_is_quiet(monkeypatch):
    async def fake_hello(ip, port, hostname):
        return ServerHello(
            compression=COMPRESSION_NULL,
            extensions={EXT_SUPPORTED_VERSIONS: b"\x03\x04"},
        )
    monkeypatch.setattr(HandshakeHardeningPlugin, "_server_hello", staticmethod(fake_hello))
    assert await HandshakeHardeningPlugin().check(None, _host([_port()])) == []
