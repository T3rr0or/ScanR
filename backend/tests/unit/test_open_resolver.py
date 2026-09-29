"""Open recursive DNS resolver detection.

Pins the DNS wire format we send and the reply classifier: only a NOERROR with an
answer to a name the host cannot be authoritative for is treated as recursion,
and the transaction id must match ours.
"""
from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from scanr.plugins.network.open_resolver import (
    OpenResolverPlugin,
    encode_query,
    parse_response,
    _RCODE_NOERROR,
)


def _port(number=53, state="open", protocol="udp"):
    return SimpleNamespace(number=number, state=state, protocol=protocol)


def _host(ports, ip="192.0.2.10"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def _response(txid, *, qr=True, rcode=0, ra=True, ancount=1):
    flags = 0
    if qr:
        flags |= 0x8000
    if ra:
        flags |= 0x0080
    flags |= rcode & 0x0F
    return struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0)


# ── wire format ──────────────────────────────────────────────────────────────

def test_query_sets_recursion_desired_and_edns():
    packet = encode_query("www.example.com", 1, 0x1234)
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    assert txid == 0x1234
    assert flags & 0x0100          # RD set
    assert qd == 1
    assert ar == 1                 # the OPT record


def test_query_encodes_the_name_as_labels():
    packet = encode_query("a.bc", 1, 1)
    assert b"\x01a\x02bc\x00" in packet


# ── reply classification ─────────────────────────────────────────────────────

def test_matching_txid_noerror_with_answers_is_recursion():
    rcode, ra, answers = parse_response(_response(0x1337, rcode=0, ancount=2), 0x1337)
    assert rcode == _RCODE_NOERROR and ra is True and answers == 2


def test_a_reply_for_a_different_txid_is_rejected():
    assert parse_response(_response(0x9999), 0x1337) is None


def test_a_query_not_a_response_is_rejected():
    assert parse_response(_response(0x1337, qr=False), 0x1337) is None


@pytest.mark.parametrize("raw", [None, b"", b"\x00\x01"])
def test_truncated_or_missing_reply_is_rejected(raw):
    assert parse_response(raw, 0x1337) is None


# ── plugin behaviour ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refused_recursion_produces_no_finding(monkeypatch):
    async def fake_query(self, ip, name, qtype, txid):
        return _response(txid, rcode=5, ancount=0), 30  # REFUSED
    monkeypatch.setattr(OpenResolverPlugin, "_query", fake_query)
    assert await OpenResolverPlugin().check(None, _host([_port()])) == []


@pytest.mark.asyncio
async def test_noerror_with_no_answers_is_not_recursion(monkeypatch):
    async def fake_query(self, ip, name, qtype, txid):
        return _response(txid, rcode=0, ancount=0), 30
    monkeypatch.setattr(OpenResolverPlugin, "_query", fake_query)
    assert await OpenResolverPlugin().check(None, _host([_port()])) == []


@pytest.mark.asyncio
async def test_open_resolver_is_reported(monkeypatch):
    async def fake_query(self, ip, name, qtype, txid):
        return _response(txid, rcode=0, ra=True, ancount=1), 30
    async def fake_ampl(self, ip):
        return 30, 3000, 100.0
    monkeypatch.setattr(OpenResolverPlugin, "_query", fake_query)
    monkeypatch.setattr(OpenResolverPlugin, "_measure_amplification", fake_ampl)
    findings = await OpenResolverPlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].severity.value == "high"        # 100x → high
    assert findings[0].port_number == 53
    assert findings[0].protocol == "udp"


@pytest.mark.asyncio
async def test_closed_port_is_not_probed(monkeypatch):
    async def fail(self, *a):
        raise AssertionError("must not probe a closed port")
    monkeypatch.setattr(OpenResolverPlugin, "_query", fail)
    assert await OpenResolverPlugin().check(None, _host([_port(state="closed")])) == []
