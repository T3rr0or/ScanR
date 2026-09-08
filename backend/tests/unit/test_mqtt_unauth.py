"""MQTT anonymous access detection.

These tests pin the CONNACK parsing (only recognised return codes count, and a
non-CONNACK first byte is refused rather than guessed at), and the plugin
behaviour: only return code 0x00 ("Connection Accepted") is a finding, and the
$SYS SUBSCRIBE result upgrades the evidence but is never required to report.
"""
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services.mqtt_unauth import (
    MqttUnauthPlugin,
    _build_connect,
    _build_subscribe,
    _parse_connack,
    _suback_granted,
)


def _connack(code: int) -> bytes:
    """CONNACK: fixed header 0x20 0x02, session-present 0x00, return code."""
    return bytes([0x20, 0x02, 0x00, code])


def _suback(granted_code: int = 0x00, packet_id: int = 1) -> bytes:
    return bytes([0x90, 0x03]) + packet_id.to_bytes(2, "big") + bytes([granted_code])


def _port(number, state="open"):
    return SimpleNamespace(number=number, state=state, banner=None, service=None)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


# ── wire format ──────────────────────────────────────────────────────────────

def test_connect_packet_has_no_credential_flags():
    packet = _build_connect()
    assert packet[0] == 0x10  # CONNECT fixed header

    # Decode the variable-length remaining-length header (1+ bytes, MSB=continue)
    # so the body offset is correct regardless of client-id length.
    idx = 1
    while True:
        b = packet[idx]
        idx += 1
        if not (b & 0x80):
            break
    body = packet[idx:]
    # body layout: 2(name len) + 4("MQTT") + 1(level) + 1(flags) + 2(keepalive) + ...
    connect_flags = body[7]
    assert connect_flags == 0x02  # clean session only — no username/password bits


def test_subscribe_packet_targets_sys_tree():
    packet = _build_subscribe()
    assert packet[0] == 0x82
    assert b"$SYS/#" in packet


# ── CONNACK parsing ──────────────────────────────────────────────────────────

def test_parses_recognised_return_codes():
    assert _parse_connack(_connack(0x00)) == 0x00
    assert _parse_connack(_connack(0x05)) == 0x05


@pytest.mark.parametrize("raw", [
    None,
    b"",
    b"\x20\x02\x00",              # truncated — no return-code byte
    b"\x30\x02\x00\x00",          # wrong packet type (0x30 = PUBLISH)
    _connack(0x7F),               # unrecognised return code
    b"HTTP/1.1 200 OK\r\n\r\n",   # a completely different protocol on the port
])
def test_garbage_or_wrong_protocol_is_not_a_connack(raw):
    assert _parse_connack(raw) is None


def test_suback_granted_reads_the_granted_qos():
    assert _suback_granted(_suback(0x00)) is True
    assert _suback_granted(_suback(0x01)) is True
    assert _suback_granted(_suback(0x02)) is True


@pytest.mark.parametrize("raw", [
    None,
    b"",
    b"\x90\x03\x00\x01",          # truncated — missing the granted-code byte
    _suback(0x80),                 # 0x80 = subscription failure
    b"\xa0\x03\x00\x01\x00",      # wrong packet type (0xa0 = UNSUBACK)
])
def test_suback_not_granted_for_garbage_or_failure(raw):
    assert _suback_granted(raw) is False


# ── plugin behaviour ─────────────────────────────────────────────────────────

def _patch_probe(monkeypatch, plugin, result=None, exc=None):
    async def fake(self, ip, port):
        if exc is not None:
            raise exc
        return result
    monkeypatch.setattr(MqttUnauthPlugin, "_probe", fake)


@pytest.mark.asyncio
async def test_anonymous_connect_accepted_is_reported_high(monkeypatch):
    plugin = MqttUnauthPlugin()
    _patch_probe(monkeypatch, plugin, result=(_connack(0x00), _suback(0x00)))
    host = _host([_port(1883)])

    findings = await plugin.check(None, host)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.title == "MQTT Broker Allows Anonymous Access"
    assert "CONNACK 0x00" in finding.evidence
    assert "SUBACK granted" in finding.evidence
    assert "in cleartext" in finding.evidence
    assert finding.port_number == 1883
    assert finding.protocol == "tcp"


@pytest.mark.asyncio
async def test_tls_port_evidence_notes_encryption(monkeypatch):
    plugin = MqttUnauthPlugin()
    # No $SYS access this time — still a finding, just without the SUBACK note.
    _patch_probe(monkeypatch, plugin, result=(_connack(0x00), _suback(0x80)))
    host = _host([_port(8883)])

    findings = await plugin.check(None, host)

    assert len(findings) == 1
    assert "over TLS" in findings[0].evidence
    assert "SUBACK granted" not in findings[0].evidence


@pytest.mark.asyncio
async def test_broker_that_rejects_anonymous_connect_is_not_reported(monkeypatch):
    """'Not Authorized' proves the broker requires credentials — no finding."""
    plugin = MqttUnauthPlugin()
    _patch_probe(monkeypatch, plugin, result=(_connack(0x05), None))
    host = _host([_port(1883)])

    assert await plugin.check(None, host) == []


@pytest.mark.asyncio
async def test_closed_port_is_skipped_without_probing(monkeypatch):
    plugin = MqttUnauthPlugin()

    async def fail_if_called(self, ip, port):
        raise AssertionError("must not probe a closed port")

    monkeypatch.setattr(MqttUnauthPlugin, "_probe", fail_if_called)
    host = _host([_port(1883, state="closed")])

    assert await plugin.check(None, host) == []


@pytest.mark.asyncio
async def test_unreachable_port_produces_no_finding_and_no_exception(monkeypatch):
    plugin = MqttUnauthPlugin()
    _patch_probe(monkeypatch, plugin, exc=TimeoutError("connect timed out"))
    host = _host([_port(1883)])

    assert await plugin.check(None, host) == []


@pytest.mark.asyncio
async def test_wrong_protocol_reply_produces_no_finding(monkeypatch):
    """Some other service answered on 1883/8883 — never report it as MQTT."""
    plugin = MqttUnauthPlugin()
    _patch_probe(monkeypatch, plugin, result=(b"SSH-2.0-OpenSSH_9.6\r\n", None))
    host = _host([_port(1883)])

    assert await plugin.check(None, host) == []


@pytest.mark.asyncio
async def test_no_reply_at_all_produces_no_finding(monkeypatch):
    plugin = MqttUnauthPlugin()
    _patch_probe(monkeypatch, plugin, result=None)
    host = _host([_port(1883)])

    assert await plugin.check(None, host) == []
