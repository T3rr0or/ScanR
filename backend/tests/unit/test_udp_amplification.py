"""UDP reflection/amplification vector detection.

Pins each vector's response validator and the amplification maths: a reply is
only counted when it validates as the right protocol, and severity tracks the
measured factor.
"""
from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from scanr.plugins.services.udp_amplification import (
    UdpAmplificationPlugin,
    _valid_portmap,
    _valid_ripv1,
    _valid_ssdp,
    _valid_text_stream,
    _PORTMAP_XID,
    amplification_factor,
    severity_for,
    VECTORS,
)
from scanr.core.plugin_base import Severity


def _port(number, state="open", protocol="udp"):
    return SimpleNamespace(number=number, state=state, protocol=protocol)


def _host(ports, ip="192.0.2.20"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


# ── validators ───────────────────────────────────────────────────────────────

def test_portmap_reply_requires_our_xid_and_accepted_status():
    good = struct.pack("!III", _PORTMAP_XID, 1, 0) + b"\x00" * 40
    assert _valid_portmap(good)
    wrong_xid = struct.pack("!III", 0xDEAD, 1, 0) + b"\x00" * 40
    assert not _valid_portmap(wrong_xid)


def test_ripv1_reply_must_be_response_version_one_with_whole_rtes():
    assert _valid_ripv1(b"\x02\x01\x00\x00" + b"\x00" * 20)
    assert not _valid_ripv1(b"\x01\x01\x00\x00" + b"\x00" * 20)  # request, not response


def test_ssdp_reply_must_be_http_200():
    assert _valid_ssdp(b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n")
    assert not _valid_ssdp(b"NOTIFY * HTTP/1.1\r\n")


def test_text_stream_rejects_binary():
    assert _valid_text_stream(b"The quick brown fox jumps\r\n")
    assert not _valid_text_stream(b"\x00\x01\x02\x03\xff\xfe\xfd\xfc")


# ── maths ────────────────────────────────────────────────────────────────────

def test_amplification_factor_and_severity():
    assert amplification_factor(30, 3000) == 100.0
    assert amplification_factor(0, 100) == 0.0
    assert severity_for(100.0) is Severity.high
    assert severity_for(3.0) is Severity.medium


# ── plugin behaviour ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_low_amplification_is_not_reported(monkeypatch):
    async def fake_probe(self, ip, vector):
        return len(vector.request) + 1   # ratio just above 1x, below the 2x floor
    monkeypatch.setattr(UdpAmplificationPlugin, "_probe", fake_probe)
    host = _host([_port(389)])
    assert await UdpAmplificationPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_high_amplification_is_reported_high(monkeypatch):
    async def fake_probe(self, ip, vector):
        return len(vector.request) * 50
    monkeypatch.setattr(UdpAmplificationPlugin, "_probe", fake_probe)
    host = _host([_port(389)])
    findings = await UdpAmplificationPlugin().check(None, host)
    assert len(findings) == 1
    assert findings[0].severity is Severity.high
    assert findings[0].protocol == "udp"
    assert findings[0].port_number == 389


@pytest.mark.asyncio
async def test_no_reply_is_not_reported(monkeypatch):
    async def fake_probe(self, ip, vector):
        return 0
    monkeypatch.setattr(UdpAmplificationPlugin, "_probe", fake_probe)
    assert await UdpAmplificationPlugin().check(None, _host([_port(19)])) == []


@pytest.mark.asyncio
async def test_only_amplification_ports_are_probed(monkeypatch):
    probed = []
    async def fake_probe(self, ip, vector):
        probed.append(vector.port)
        return 0
    monkeypatch.setattr(UdpAmplificationPlugin, "_probe", fake_probe)
    await UdpAmplificationPlugin().check(None, _host([_port(53), _port(389), _port(1900)]))
    assert set(probed) == {389, 1900}


def test_every_vector_has_a_validator_and_remediation():
    for vector in VECTORS:
        assert callable(vector.validate)
        assert vector.remediation and vector.reference
