"""DNP3 (IEEE 1815, TCP 20000) outstation detection.

DNP3 supervises electricity/water/gas infrastructure and has no notion of an
authenticated peer, so these tests pin the same two things every ICS probe in
this suite pins: that a real outstation reply is parsed correctly, and that
the plugin never puts anything but the single documented link-status frame on
the wire. A probe that grew into something reading points or issuing
SELECT/OPERATE would be a safety regression against live grid equipment.
"""
from __future__ import annotations

import asyncio
import struct
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import dnp3_detect as dnp3


class _Ctx:
    def proxy_config(self):
        return {}


class FakeWriter:
    def __init__(self):
        self.sent = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.sent += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


class FakeReader:
    """The plugin does a single `reader.read(64)` — one buffered chunk is enough."""

    def __init__(self, data: bytes):
        self._buf = data

    async def read(self, n: int) -> bytes:
        chunk = self._buf[:n]
        self._buf = self._buf[n:]
        return chunk


def _install(monkeypatch, reader_bytes: bytes, *, fail: Exception | None = None, writer: FakeWriter | None = None):
    writer = writer or FakeWriter()

    async def fake_open_connection(ip, port):
        if fail is not None:
            raise fail
        return FakeReader(reader_bytes), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    return writer


def _host(port=20000, state="open") -> SimpleNamespace:
    return SimpleNamespace(ip="192.0.2.40", hostname=None, ports=[SimpleNamespace(number=port, state=state, banner=None, service=None)])


def _frame(control: int, destination: int, source: int) -> bytes:
    """Build a well-formed 10-byte DNP3 link-layer frame with a correct CRC,
    using the plugin's own CRC-16/DNP implementation — the algorithm is a
    fixed IEEE 1815 standard, not something this test should reimplement."""
    header = struct.pack("<BBBBHH", 0x05, 0x64, 0x05, control, destination, source)
    return header + struct.pack("<H", dnp3._dnp3_crc(header))


# ── positive detection ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_identifies_outstation_from_a_link_status_reply(monkeypatch):
    # Secondary-station reply: DIR/PRM=0, function 0x0B = STATUS OF LINK,
    # from outstation link address 1004 back to master address 0.
    reply = _frame(control=0x0B, destination=0x0000, source=1004)
    _install(monkeypatch, reply)

    findings = await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.critical
    assert finding.title == "DNP3 SCADA Outstation Exposed"
    assert "1004" in finding.evidence
    assert "STATUS OF LINK" in finding.evidence
    assert finding.port_number == 20000


@pytest.mark.asyncio
async def test_identifies_outstation_from_a_plain_ack(monkeypatch):
    reply = _frame(control=0x00, destination=0x0000, source=7)  # ACK
    _install(monkeypatch, reply)
    findings = await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host())
    assert len(findings) == 1
    assert "ACK" in findings[0].evidence


# ── safety net: no destructive traffic ever ─────────────────────────────────

def test_plugin_declares_itself_non_destructive():
    assert dnp3.Dnp3DetectPlugin.destructive is False


@pytest.mark.asyncio
async def test_sends_exactly_the_documented_link_status_request(monkeypatch):
    """Pins the exact bytes on the wire against the module docstring's own
    hex dump. REQUEST LINK STATUS is data-link only — it carries no
    transport segment or application fragment, so it cannot read a point,
    select/operate an output, or restart anything. A future change that
    smuggled application-layer bytes into this frame — or added a second
    frame — must fail here.
    """
    expected = bytes.fromhex("05 64 05 c9 00 00 00 00 36 4c")
    reply = _frame(control=0x0B, destination=0, source=1)
    writer = _install(monkeypatch, reply)

    await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host())

    assert bytes(writer.sent) == expected
    assert writer.closed is True


# ── negative paths: never a crash, never a false finding ───────────────────

@pytest.mark.asyncio
async def test_closed_port_produces_nothing(monkeypatch):
    _install(monkeypatch, b"", fail=ConnectionRefusedError())
    assert await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_truncated_response_produces_nothing_not_a_crash(monkeypatch):
    _install(monkeypatch, b"\x05\x64\x05")  # fewer than the 10-byte header
    assert await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_garbage_response_produces_nothing_not_a_crash(monkeypatch):
    _install(monkeypatch, b"\x00" * 20)
    assert await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_a_different_protocol_on_port_20000_produces_nothing(monkeypatch):
    """A banner that doesn't even start with the DNP3 start bytes."""
    _install(monkeypatch, b"220 unrelated service ready\r\n")
    assert await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_start_bytes_with_a_bad_crc_produces_nothing(monkeypatch):
    """A service that coincidentally opens with 05 64 but is not DNP3 must
    not pass — the CRC check, not just the magic bytes, is what confirms it."""
    header = struct.pack("<BBBBHH", 0x05, 0x64, 0x05, 0x0B, 0, 1004)
    bad_frame = header + b"\x00\x00"  # wrong CRC
    _install(monkeypatch, bad_frame)
    assert await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_a_reflected_request_shaped_frame_produces_nothing(monkeypatch):
    """PRM=1 means "this is a request", i.e. an echo of our own primary
    frame, not a genuine secondary-station reply — must not be reported."""
    reply = _frame(control=0xC9, destination=0, source=0)  # our own request, echoed
    _install(monkeypatch, reply)
    assert await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_closed_state_port_is_never_probed(monkeypatch):
    async def fake_open_connection(ip, port):
        raise AssertionError("should not connect to a closed port")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    findings = await dnp3.Dnp3DetectPlugin().check(_Ctx(), _host(state="closed"))
    assert findings == []
