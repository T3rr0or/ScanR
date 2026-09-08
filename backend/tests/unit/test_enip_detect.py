"""EtherNet/IP (CIP) device identity detection, TCP 44818.

EtherNet/IP has no authentication of its own, so the plugin's safety margin
is entirely in what it sends: a single List Identity discovery frame, never
RegisterSession or the SendRRData/SendUnitData frames that carry real CIP
explicit messaging (including the Identity Object Reset service, which
reboots the controller). These tests pin a realistic identity reply parsing
correctly and pin the exact request bytes so that margin can't erode silently.
"""
from __future__ import annotations

import asyncio
import struct
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import enip_detect as enip


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


def _install(monkeypatch, reader_bytes: bytes, *, fail: Exception | None = None, writer: FakeWriter | None = None):
    writer = writer or FakeWriter()

    async def fake_open_connection(ip, port):
        if fail is not None:
            raise fail
        return FakeReader(reader_bytes), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    return writer


def _host(enip_state="open", io_state=None) -> SimpleNamespace:
    ports = [SimpleNamespace(number=44818, state=enip_state, banner=None, service=None)]
    if io_state is not None:
        ports.append(SimpleNamespace(number=2222, state=io_state, banner=None, service=None))
    return SimpleNamespace(ip="192.0.2.50", hostname=None, ports=ports)


def _list_identity_reply(
    vendor_id=1,
    device_type=0x0E,
    product_code=54,
    revision=(33, 11),
    serial=0x6F4E2A10,
    product_name="1756-L83E/B",
    status=0x0060,
    encap_version=1,
) -> bytes:
    """Build a captured-style List Identity reply — the inverse of
    `_parse_list_identity` — from an Identity Object's fields."""
    name_bytes = product_name.encode("ascii")
    item = (
        struct.pack("<H", encap_version)
        + b"\x00" * 16  # sockaddr_in, unused by the parser
        + struct.pack("<HHH", vendor_id, device_type, product_code)
        + bytes([revision[0], revision[1]])
        + struct.pack("<HI", status, serial)
        + bytes([len(name_bytes)])
        + name_bytes
    )
    cip_item = struct.pack("<HH", enip._ITEM_CIP_IDENTITY, len(item)) + item
    command_specific = struct.pack("<H", 1) + cip_item  # item count = 1
    header = struct.pack("<HHII8sI", enip._CMD_LIST_IDENTITY, len(command_specific), 0, 0, b"\x00" * 8, 0)
    return header + command_specific


# ── positive detection ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_identifies_device_from_a_captured_style_list_identity_reply(monkeypatch):
    reply = _list_identity_reply(
        vendor_id=1,
        device_type=0x0E,
        product_code=54,
        revision=(33, 11),
        serial=0x6F4E2A10,
        product_name="1756-L83E/B",
    )
    _install(monkeypatch, reply)

    findings = await enip.EnipDetectPlugin().check(_Ctx(), _host())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.title == "EtherNet/IP CIP Device Exposed"
    assert "1756-L83E/B" in finding.evidence
    assert "Rockwell Automation/Allen-Bradley" in finding.evidence
    assert "Programmable Logic Controller" in finding.evidence
    assert "33.11" in finding.evidence
    assert "6f4e2a10" in finding.evidence.lower()
    assert finding.port_number == 44818


@pytest.mark.asyncio
async def test_unknown_vendor_is_reported_by_number_not_guessed(monkeypatch):
    reply = _list_identity_reply(vendor_id=9999, device_type=0x02, product_name="Generic Drive")
    _install(monkeypatch, reply)
    findings = await enip.EnipDetectPlugin().check(_Ctx(), _host())
    assert len(findings) == 1
    assert "9999" in findings[0].evidence or "0x270f" in findings[0].evidence.lower()


@pytest.mark.asyncio
async def test_open_implicit_io_port_is_reported_as_evidence_only(monkeypatch):
    """UDP 2222 carries live cyclic process data and is never probed — its
    openness is only ever mentioned, not queried."""
    reply = _list_identity_reply()
    _install(monkeypatch, reply)
    findings = await enip.EnipDetectPlugin().check(_Ctx(), _host(io_state="open"))
    assert len(findings) == 1
    assert "2222" in findings[0].evidence


# ── safety net: no destructive traffic ever ─────────────────────────────────

def test_plugin_declares_itself_non_destructive():
    assert enip.EnipDetectPlugin.destructive is False


@pytest.mark.asyncio
async def test_sends_exactly_the_documented_list_identity_request(monkeypatch):
    """Pins the exact bytes on the wire against the module docstring's own
    hex dump. List Identity carries no CIP request path, so it registers no
    session and writes no object attribute. A future change that added
    RegisterSession, SendRRData, or any real CIP explicit message (a tag
    write or the Identity Object Reset service) must fail here.
    """
    expected = bytes.fromhex(
        "63 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    )
    assert len(expected) == 24
    reply = _list_identity_reply()
    writer = _install(monkeypatch, reply)

    await enip.EnipDetectPlugin().check(_Ctx(), _host())

    assert bytes(writer.sent) == expected
    assert writer.closed is True


@pytest.mark.asyncio
async def test_udp_2222_is_never_connected_to(monkeypatch):
    """Even when the implicit I/O port is open, only 44818 is ever dialed."""
    dialed_ports: list[int] = []

    async def fake_open_connection(ip, port):
        dialed_ports.append(port)
        return FakeReader(_list_identity_reply()), FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    await enip.EnipDetectPlugin().check(_Ctx(), _host(io_state="open"))
    assert dialed_ports == [44818]


# ── negative paths: never a crash, never a false finding ───────────────────

@pytest.mark.asyncio
async def test_closed_port_produces_nothing(monkeypatch):
    _install(monkeypatch, b"", fail=ConnectionRefusedError())
    assert await enip.EnipDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_truncated_response_produces_nothing_not_a_crash(monkeypatch):
    _install(monkeypatch, b"\x63\x00\x00\x00")  # far short of the 24-byte header
    assert await enip.EnipDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_garbage_response_produces_nothing_not_a_crash(monkeypatch):
    _install(monkeypatch, b"\xaa" * 40)
    assert await enip.EnipDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_a_different_protocol_on_port_44818_produces_nothing(monkeypatch):
    """A plain banner, nowhere near the encapsulation header shape."""
    _install(monkeypatch, b"220 unrelated service ready\r\n")
    assert await enip.EnipDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_error_status_reply_produces_nothing(monkeypatch):
    """The device answered List Identity but with a nonzero status — the
    reply must not be read as a successful identification."""
    header = struct.pack("<HHII8sI", enip._CMD_LIST_IDENTITY, 0, 0, 0x0001, b"\x00" * 8, 0)
    _install(monkeypatch, header)
    assert await enip.EnipDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_wrong_command_reply_produces_nothing(monkeypatch):
    """Some other EtherNet/IP command (e.g. an unsolicited RegisterSession
    reply) echoed back on 44818 must not be mistaken for List Identity."""
    header = struct.pack("<HHII8sI", 0x0065, 0, 0, 0, b"\x00" * 8, 0)  # RegisterSession
    _install(monkeypatch, header)
    assert await enip.EnipDetectPlugin().check(_Ctx(), _host()) == []


@pytest.mark.asyncio
async def test_closed_state_port_is_never_probed(monkeypatch):
    async def fake_open_connection(ip, port):
        raise AssertionError("should not connect to a closed port")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    findings = await enip.EnipDetectPlugin().check(_Ctx(), _host(enip_state="closed"))
    assert findings == []
