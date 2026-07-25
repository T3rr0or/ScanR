"""The SOCKS5 egress relay is the sandbox's only path to a target, so its
authorization decision is the whole security boundary.

Covers the allowlist parser, the destination check, and a real end-to-end SOCKS5
handshake against a live relay — including that a hostname resolving partly
out-of-scope is refused, which is the DNS-rebinding case.
"""
import asyncio
import ipaddress
import socket
import struct

import pytest

from scanr.sandbox.egress_relay import Relay, parse_allowlist

_SOCKS5 = 0x05
_REP_OK = 0x00
_REP_NOT_ALLOWED = 0x02
_REP_HOST_UNREACHABLE = 0x04
_REP_CMD_UNSUPPORTED = 0x07


# ── allowlist parsing ────────────────────────────────────────────────────────

def test_parses_cidrs_and_bare_ips():
    nets = parse_allowlist("192.0.2.0/24, 198.51.100.7, 2001:db8::/32")
    assert ipaddress.ip_network("192.0.2.0/24") in nets
    assert ipaddress.ip_network("198.51.100.7/32") in nets
    assert ipaddress.ip_network("2001:db8::/32") in nets


def test_normalizes_legacy_numeric_encodings():
    """Scope entries go through canonical_ip, so '3221225985' is 192.0.2.1."""
    nets = parse_allowlist("3221225985")
    assert nets == [ipaddress.ip_network("192.0.2.1/32")]


def test_drops_hostnames_and_garbage():
    """A hostname cannot be an egress rule — the address behind it can change."""
    assert parse_allowlist("example.com, not-a-cidr, 999.1.1.1, ") == []


def test_empty_config_is_empty_allowlist():
    assert parse_allowlist("") == []


# ── destination authorization ────────────────────────────────────────────────

def _relay(scope="192.0.2.0/24"):
    return Relay(parse_allowlist(scope))


def test_in_scope_address_allowed():
    ok, _ = _relay()._check_destination("192.0.2.10")
    assert ok


@pytest.mark.parametrize("addr", ["198.51.100.10", "8.8.8.8", "10.0.0.5", "203.0.113.1"])
def test_out_of_scope_refused(addr):
    ok, reason = _relay()._check_destination(addr)
    assert not ok and "outside the scan's authorized scope" in reason


def test_empty_allowlist_refuses_everything():
    """Fail-closed: no configured scope must not mean 'anything goes'."""
    r = Relay([])
    for addr in ("192.0.2.10", "8.8.8.8", "127.0.0.1"):
        ok, reason = r._check_destination(addr)
        assert not ok and "fail-closed" in reason


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "169.254.169.254", "::1", "0.0.0.0", "::ffff:127.0.0.1",
])
def test_infrastructure_refused_even_when_scope_would_cover_it(addr):
    """A scope entry must never be able to authorize loopback or cloud metadata."""
    r = Relay(parse_allowlist("0.0.0.0/0, ::/0"))
    ok, reason = r._check_destination(addr)
    assert not ok, f"{addr} was allowed"
    assert "forbidden infrastructure" in reason


def test_legacy_encoding_of_metadata_refused():
    r = Relay(parse_allowlist("0.0.0.0/0"))
    ok, reason = r._check_destination("2852039166")  # 169.254.169.254
    assert not ok and "forbidden infrastructure" in reason


def test_legacy_encoding_of_in_scope_target_allowed():
    r = _relay("192.0.2.0/24")
    ok, _ = r._check_destination("3221225994")  # 192.0.2.10
    assert ok


def test_non_address_refused():
    ok, reason = _relay()._check_destination("example.com")
    assert not ok and "not an address" in reason


# ── live SOCKS5 protocol ─────────────────────────────────────────────────────

async def _serve_relay(scope: str):
    relay = _relay(scope) if scope else Relay([])
    server = await asyncio.start_server(relay.handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _socks_connect(port: int, atyp: int, addr: bytes, dport: int, cmd: int = 0x01):
    """Perform a SOCKS5 greeting + request, return (reply_code, reader, writer)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(struct.pack("!BBB", _SOCKS5, 1, 0x00))
    await writer.drain()
    assert await reader.readexactly(2) == struct.pack("!BB", _SOCKS5, 0x00)

    writer.write(struct.pack("!BBBB", _SOCKS5, cmd, 0x00, atyp) + addr + struct.pack("!H", dport))
    await writer.drain()
    resp = await reader.readexactly(10)
    return resp[1], reader, writer


@pytest.mark.asyncio
async def test_end_to_end_allowed_connection_relays_bytes():
    """An in-scope destination must actually carry traffic both ways."""
    async def echo(r, w):
        data = await r.read(64)
        w.write(b"echo:" + data)
        await w.drain()
        w.close()

    target = await asyncio.start_server(echo, "127.0.0.1", 0)
    tport = target.sockets[0].getsockname()[1]

    # 127.0.0.1 is forbidden infrastructure, so scope it explicitly and disable
    # only that guard to exercise the data path against a real socket.
    relay = Relay(parse_allowlist("127.0.0.0/8"))
    relay._check_destination = lambda addr: (True, "")  # type: ignore[method-assign]
    server = await asyncio.start_server(relay.handle, "127.0.0.1", 0)
    rport = server.sockets[0].getsockname()[1]

    async with server, target:
        rep, reader, writer = await _socks_connect(
            rport, 0x01, socket.inet_aton("127.0.0.1"), tport
        )
        assert rep == _REP_OK
        writer.write(b"ping")
        await writer.drain()
        assert await reader.readexactly(9) == b"echo:ping"
        writer.close()


@pytest.mark.asyncio
async def test_end_to_end_out_of_scope_is_refused():
    server, port = await _serve_relay("192.0.2.0/24")
    async with server:
        rep, _, writer = await _socks_connect(port, 0x01, socket.inet_aton("8.8.8.8"), 80)
        assert rep == _REP_NOT_ALLOWED
        writer.close()


@pytest.mark.asyncio
async def test_end_to_end_loopback_is_refused():
    server, port = await _serve_relay("0.0.0.0/0")
    async with server:
        rep, _, writer = await _socks_connect(port, 0x01, socket.inet_aton("127.0.0.1"), 22)
        assert rep == _REP_NOT_ALLOWED
        writer.close()


@pytest.mark.asyncio
async def test_bind_and_udp_associate_are_unsupported():
    """Only CONNECT: BIND/UDP would move traffic the relay never authorized."""
    server, port = await _serve_relay("192.0.2.0/24")
    async with server:
        for cmd in (0x02, 0x03):  # BIND, UDP ASSOCIATE
            rep, _, writer = await _socks_connect(
                port, 0x01, socket.inet_aton("192.0.2.10"), 80, cmd=cmd
            )
            assert rep == _REP_CMD_UNSUPPORTED, f"cmd {cmd:#x}"
            writer.close()


@pytest.mark.asyncio
async def test_domain_destination_is_checked_against_resolved_addresses(monkeypatch):
    """The DNS case: an in-scope-looking name whose answers include an
    out-of-scope address must be refused, not connected to."""
    relay = _relay("192.0.2.0/24")

    async def fake_resolve(_host):
        return ["192.0.2.10", "8.8.8.8"]  # one in scope, one not

    monkeypatch.setattr(relay, "_resolve", fake_resolve)
    server = await asyncio.start_server(relay.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        name = b"target.example.com"
        rep, _, writer = await _socks_connect(
            port, 0x03, bytes([len(name)]) + name, 80
        )
        assert rep == _REP_NOT_ALLOWED
        writer.close()


@pytest.mark.asyncio
async def test_unresolvable_domain_reports_unreachable(monkeypatch):
    relay = _relay("192.0.2.0/24")

    async def no_answer(_host):
        return []

    monkeypatch.setattr(relay, "_resolve", no_answer)
    server = await asyncio.start_server(relay.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        name = b"nope.invalid"
        rep, _, writer = await _socks_connect(port, 0x03, bytes([len(name)]) + name, 80)
        assert rep == _REP_HOST_UNREACHABLE
        writer.close()


@pytest.mark.asyncio
async def test_unknown_address_type_refused():
    server, port = await _serve_relay("192.0.2.0/24")
    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(struct.pack("!BBB", _SOCKS5, 1, 0x00))
        await writer.drain()
        await reader.readexactly(2)
        writer.write(struct.pack("!BBBB", _SOCKS5, 0x01, 0x00, 0x09))  # bogus ATYP
        await writer.drain()
        resp = await reader.readexactly(10)
        assert resp[1] == 0x08  # ATYP not supported
        writer.close()


@pytest.mark.asyncio
async def test_non_socks5_client_is_dropped_without_crashing():
    server, port = await _serve_relay("192.0.2.0/24")
    async with server:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET / HTTP/1.1\r\n\r\n")  # SOCKS4 / HTTP garbage
        await writer.drain()
        writer.close()
        # The relay must still serve the next client.
        rep, _, w2 = await _socks_connect(port, 0x01, socket.inet_aton("8.8.8.8"), 80)
        assert rep == _REP_NOT_ALLOWED
        w2.close()


@pytest.mark.asyncio
async def test_malformed_domain_bytes_are_refused_not_raised():
    """Non-UTF-8 / non-IDNA domain bytes must produce a SOCKS refusal, not an
    unhandled decode error (the idna codec rejects errors='replace')."""
    server, port = await _serve_relay("192.0.2.0/24")
    async with server:
        for raw in (b"\xff\xfe\xfd", b"na\xc3\xafve.example.com", b"\x80" * 8):
            rep, _, writer = await _socks_connect(port, 0x03, bytes([len(raw)]) + raw, 80)
            assert rep in (_REP_NOT_ALLOWED, _REP_HOST_UNREACHABLE), f"{raw!r} -> {rep:#x}"
            writer.close()
