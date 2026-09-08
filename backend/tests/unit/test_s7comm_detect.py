"""Siemens S7comm (ISO-TSAP, TCP 102) detection.

These tests pin two things: that a genuine module-identification SZL reply is
parsed into the right vendor/hardware/firmware fields, and — because this
plugin talks to PLCs driving physical processes — that the exact bytes it
puts on the wire never drift from the three-frame, read-only exchange the
module docstring documents. A probe that silently grew a write/control frame
would be a safety regression, not just a test failure.
"""
from __future__ import annotations

import asyncio
import struct
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import s7comm_detect as s7


class _Ctx:
    def proxy_config(self):
        return {}


class FakeWriter:
    """Captures every byte written so tests can assert on the wire format."""

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
    """Feeds back a pre-built byte stream, mimicking asyncio.StreamReader."""

    def __init__(self, data: bytes):
        self._buf = data

    async def readexactly(self, n: int) -> bytes:
        if len(self._buf) < n:
            partial = bytes(self._buf)
            self._buf = b""
            raise asyncio.IncompleteReadError(partial, n)
        chunk = self._buf[:n]
        self._buf = self._buf[n:]
        return chunk


def _install(monkeypatch, reader_bytes: bytes | None, writer: FakeWriter, *, fail: Exception | None = None):
    async def fake_open_connection(ip, port):
        if fail is not None:
            raise fail
        return FakeReader(reader_bytes), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)


def _host(port=102, state="open") -> SimpleNamespace:
    return SimpleNamespace(ip="192.0.2.30", hostname=None, ports=[SimpleNamespace(number=port, state=state, banner=None, service=None)])


# ── building a realistic COTP/S7 exchange (the inverse of the plugin's own parser) ──

def _cotp_connect_confirm() -> bytes:
    """TPKT + COTP CC (0xD0) — the only reply that lets the handshake proceed."""
    cotp = bytes([0x02, 0xD0, 0x80])  # LI, PDU type = Connect Confirm, TPDU-NR/EOT
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(cotp)) + cotp


def _s7_setup_ack() -> bytes:
    """TPKT + COTP DT + S7 'Ack Data' header for Setup Communication."""
    cotp = bytes([0x02, 0xF0, 0x80])
    s7_header = bytes([0x32, 0x03, 0x00, 0x00, 0x00, 0x01]) + struct.pack(">HH", 0, 0)
    body = cotp + s7_header
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(body)) + body


def _record(index: int, mlfb: str, firmware: tuple[int, int, int] | None = None) -> bytes:
    mlfb_bytes = mlfb.encode("ascii").ljust(20, b"\x00")[:20]
    rec = struct.pack(">H", index) + mlfb_bytes + b"\x00\x00"  # 24 bytes so far
    if firmware:
        rec += bytes([firmware[0], firmware[1], 0x00, firmware[2]])
    else:
        rec += b"\x00\x00\x00\x00"
    assert len(rec) == 28
    return rec


def _szl_reply(module="6ES7 315-2AG10-0AB0", hardware="6ES7 315-2AG10-0AB0", firmware=(3, 2, 6)) -> bytes:
    """A module-identification (SZL 0x0011) reply, built field-by-field to
    match what `_parse_szl_response` expects — the inverse of that function."""
    records = _record(0x0001, module) + _record(0x0006, hardware) + _record(0x0007, "", firmware)
    payload = struct.pack(">HHHH", 0x0011, 0x0000, 28, 3) + records
    block = bytes([0xFF, 0x09]) + struct.pack(">H", len(payload)) + payload
    param = bytes([0x00, 0x01, 0x12, 0x08, 0x11, 0x44, 0x01, 0x00, 0x00, 0x00]) + struct.pack(">H", 0x0000)
    s7_header = bytes([0x32, 0x07, 0x00, 0x00, 0x00, 0x01]) + struct.pack(">HH", len(param), len(block))
    cotp = bytes([0x02, 0xF0, 0x80])
    body = cotp + s7_header + param + block
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(body)) + body


def _full_exchange(**szl_kwargs) -> bytes:
    return _cotp_connect_confirm() + _s7_setup_ack() + _szl_reply(**szl_kwargs)


# ── positive detection ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_identifies_plc_from_a_captured_style_szl_reply(monkeypatch):
    writer = FakeWriter()
    _install(monkeypatch, _full_exchange(module="6ES7 315-2AG10-0AB0", hardware="6ES7 315-2AG10-0AB0", firmware=(3, 2, 6)), writer)

    findings = await s7.S7CommDetectPlugin().check(_Ctx(), _host())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.critical
    assert finding.title == "Siemens S7comm PLC Exposed"
    assert "6ES7 315-2AG10-0AB0" in finding.evidence
    assert "V3.2.6" in finding.evidence
    assert finding.port_number == 102


# ── safety net: no destructive traffic ever ─────────────────────────────────

def test_plugin_declares_itself_non_destructive():
    assert s7.S7CommDetectPlugin.destructive is False


@pytest.mark.asyncio
async def test_sends_exactly_the_documented_read_only_three_frame_exchange(monkeypatch):
    """Pins the exact bytes on the wire against the module docstring's own
    hex dump, independent of the module's internal constants, so a future
    change that adds — or subtly mutates into — a write/control/PLC-stop
    frame is caught here rather than on a live controller.
    """
    # COTP CR: TSAP 0x0100 -> 0x0102 (rack 0 / slot 2), TPDU size 2^10. Opens
    # a transport connection only — no S7 payload is possible without it.
    expected_cotp_cr = bytes.fromhex(
        "03 00 00 16 11 e0 00 00 00 01 00 c1 02 01 00 c2 02 01 02 c0 01 0a"
    )
    # S7 "Setup communication" (Job, function 0xf0): negotiates PDU size,
    # reads and writes nothing on the CPU.
    expected_setup = bytes.fromhex(
        "03 00 00 19 02 f0 80 32 01 00 00 00 01 00 08 00 00 f0 00 00 01 00 01 01 e0"
    )
    # S7 "Read SZL" (Userdata, CPU functions 0x11, subfunction 0x44) for
    # SZL-ID 0x0011 index 0x0000 — module identification, the CPU's own
    # read-only diagnostic buffer. Never a read/write-variable or PLC
    # control (STOP/START) function.
    expected_read_szl = bytes.fromhex(
        "03 00 00 21 02 f0 80 32 07 00 00 00 01 00 08 00 08"
        "00 01 12 04 11 44 01 00 ff 09 00 04 00 11 00 00"
    )
    expected = expected_cotp_cr + expected_setup + expected_read_szl

    writer = FakeWriter()
    _install(monkeypatch, _full_exchange(), writer)
    await s7.S7CommDetectPlugin().check(_Ctx(), _host())

    assert bytes(writer.sent) == expected
    assert writer.closed is True


# ── negative paths: never a crash, never a false finding ───────────────────

@pytest.mark.asyncio
async def test_closed_port_produces_nothing(monkeypatch):
    _install(monkeypatch, b"", FakeWriter(), fail=ConnectionRefusedError())
    assert await s7.S7CommDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_truncated_response_produces_nothing_not_a_crash(monkeypatch):
    # A COTP CR was answered, but the connection died mid TPKT header.
    _install(monkeypatch, _cotp_connect_confirm()[:5], FakeWriter())
    assert await s7.S7CommDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_garbage_response_produces_nothing_not_a_crash(monkeypatch):
    _install(monkeypatch, b"\xff" * 40, FakeWriter())
    assert await s7.S7CommDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_a_different_protocol_on_port_102_produces_nothing(monkeypatch):
    """Some other TCP service happens to be listening on 102; its banner must
    not be mistaken for a COTP Connect Confirm."""
    banner = b"220 unrelated-ftp-like service ready\r\n"
    _install(monkeypatch, banner, FakeWriter())
    assert await s7.S7CommDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_connect_confirm_rejected_produces_nothing(monkeypatch):
    """A PLC that rejects the TSAP (Disconnect Request, 0x80) must not be
    treated as identified — the handshake stops there by design."""
    cotp = bytes([0x02, 0x80, 0x80])
    reject = bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(cotp)) + cotp
    _install(monkeypatch, reject, FakeWriter())
    assert await s7.S7CommDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_closed_state_port_is_never_probed(monkeypatch):
    """When the scan's own port table says 102 is closed, the plugin must not
    attempt a connection at all."""
    attempted = False

    async def fake_open_connection(ip, port):
        nonlocal attempted
        attempted = True
        raise AssertionError("should not connect to a closed port")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    findings = await s7.S7CommDetectPlugin().check(_Ctx(), _host(state="closed"))
    assert findings == []
    assert attempted is False
