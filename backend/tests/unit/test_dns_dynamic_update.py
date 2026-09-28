"""Unauthenticated DNS dynamic update detection.

Pins the RFC 2136 UPDATE encoding (empty update section, so nothing is created),
the rcode parser, and the acceptance logic: only NOERROR to our own transaction
counts, and an authoritative REFUSED stops the search.
"""
from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from scanr.plugins.services.dns_dynamic_update import (
    DnsDynamicUpdatePlugin,
    RCODE_NOERROR,
    RCODE_REFUSED,
    RCODE_NOTAUTH,
    encode_empty_update,
    parse_rcode,
    zone_candidates,
)

_OPCODE_UPDATE = 5


def _port(number=53, state="open", protocol="udp"):
    return SimpleNamespace(number=number, state=state, protocol=protocol)


def _host(ports, hostname="host.corp.example.com", ip="192.0.2.30"):
    return SimpleNamespace(ip=ip, hostname=hostname, ports=ports)


def _reply(txid, rcode):
    flags = 0x8000 | (_OPCODE_UPDATE << 11) | (rcode & 0x0F)
    return struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)


# ── encoding ─────────────────────────────────────────────────────────────────

def test_update_has_opcode_5_and_an_empty_update_section():
    packet = encode_empty_update("example.com", 0x7000)
    txid, flags, zocount, prcount, upcount, adcount = struct.unpack("!HHHHHH", packet[:12])
    assert txid == 0x7000
    assert (flags >> 11) & 0x0F == _OPCODE_UPDATE
    assert zocount == 1
    assert upcount == 0        # nothing to add — this is why nothing is created


def test_zone_candidates_walk_up_the_name():
    assert zone_candidates("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]


# ── rcode parsing ────────────────────────────────────────────────────────────

def test_parse_matches_txid_and_opcode():
    assert parse_rcode(_reply(0x7000, RCODE_NOERROR), 0x7000) == RCODE_NOERROR


def test_wrong_txid_is_rejected():
    assert parse_rcode(_reply(0x1111, RCODE_NOERROR), 0x7000) is None


@pytest.mark.parametrize("raw", [None, b"", b"\x70\x00\x00"])
def test_truncated_reply_is_rejected(raw):
    assert parse_rcode(raw, 0x7000) is None


# ── plugin behaviour ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_noerror_is_reported_high(monkeypatch):
    async def fake_probe(self, ip, zone, txid):
        return RCODE_NOERROR
    monkeypatch.setattr(DnsDynamicUpdatePlugin, "_probe", fake_probe)
    findings = await DnsDynamicUpdatePlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert findings[0].protocol == "udp"


@pytest.mark.asyncio
async def test_refused_stops_and_reports_nothing(monkeypatch):
    calls = []
    async def fake_probe(self, ip, zone, txid):
        calls.append(zone)
        return RCODE_REFUSED
    monkeypatch.setattr(DnsDynamicUpdatePlugin, "_probe", fake_probe)
    findings = await DnsDynamicUpdatePlugin().check(None, _host([_port()]))
    assert findings == []
    assert len(calls) == 1     # an authoritative refusal is final


@pytest.mark.asyncio
async def test_notauth_tries_parent_zones(monkeypatch):
    async def fake_probe(self, ip, zone, txid):
        return RCODE_NOERROR if zone == "example.com" else RCODE_NOTAUTH
    monkeypatch.setattr(DnsDynamicUpdatePlugin, "_probe", fake_probe)
    findings = await DnsDynamicUpdatePlugin().check(None, _host([_port()]))
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_bare_ip_target_is_skipped(monkeypatch):
    async def fail(self, *a):
        raise AssertionError("no hostname → no zone to name")
    monkeypatch.setattr(DnsDynamicUpdatePlugin, "_probe", fail)
    host = SimpleNamespace(ip="192.0.2.30", hostname=None, ports=[_port()])
    assert await DnsDynamicUpdatePlugin().check(None, host) == []
