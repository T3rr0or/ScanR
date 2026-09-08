"""Open X11 display detection (TCP 6000-6005).

Pins the connection-setup reply parser (only a Success reply with the X11
major version and a real screen count counts as "open") and that a Failed or
Authenticate reply — the server asking for MIT-MAGIC-COOKIE-1 — is treated as
correctly configured, never as open.
"""
import struct
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services.x11_open import (
    X11OpenPlugin,
    X11_PORTS,
    _SETUP_REQUEST,
    _parse_setup_reply,
)


def _success(vendor: bytes = b"The X.Org Foundation", release: int = 12010004, screens: int = 1) -> bytes:
    buf = bytearray(40 + len(vendor))
    buf[0] = 1  # Success
    struct.pack_into("<HH", buf, 2, 11, 0)      # protocol-major, protocol-minor
    struct.pack_into("<I", buf, 8, release)     # release-number
    struct.pack_into("<H", buf, 24, len(vendor))  # vendor length
    buf[28] = screens
    buf[40:40 + len(vendor)] = vendor
    return bytes(buf)


def _failed(reason: bytes = b"Client rejected") -> bytes:
    header = bytes([0, len(reason)]) + struct.pack("<HH", 11, 0) + b"\x00\x00"
    return header + reason


def _authenticate() -> bytes:
    return bytes([2]) + b"\x00" * 7


def _port(number, state="open"):
    return SimpleNamespace(number=number, state=state, banner=None, service=None)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


# ── wire format ──────────────────────────────────────────────────────────────

def test_setup_request_carries_empty_authorisation():
    # byte-order 'l', pad, major=11, minor=0, auth-name-len=0, auth-data-len=0
    assert _SETUP_REQUEST == struct.pack("<BBHHHH2x", 0x6C, 0, 11, 0, 0, 0)
    assert len(_SETUP_REQUEST) == 12


# ── reply parsing ─────────────────────────────────────────────────────────────

def test_parses_a_success_reply():
    parsed = _parse_setup_reply(_success(vendor=b"MIT X Consortium", screens=2))
    assert parsed["status"] == 1
    assert parsed["vendor"] == "MIT X Consortium"
    assert parsed["screens"] == 2
    assert parsed["major"] == 11


def test_parses_a_failed_reply():
    parsed = _parse_setup_reply(_failed(b"No MIT-MAGIC-COOKIE-1 supplied"))
    assert parsed["status"] == 0
    assert "MIT-MAGIC-COOKIE" in parsed["reason"]


def test_parses_an_authenticate_reply():
    assert _parse_setup_reply(_authenticate()) == {"status": 2}


def test_success_with_zero_screens_is_not_a_valid_reply():
    """A real Success reply always describes at least one screen."""
    assert _parse_setup_reply(_success(screens=0)) is None


@pytest.mark.parametrize("raw", [
    None,
    b"",
    b"\x01\x00\x0b",                                   # too short (<8 bytes)
    b"\x03" + b"\x00" * 10,                             # status byte 3 is undefined
    struct.pack("<BBHHHH", 1, 0, 12, 0, 0, 0) + b"\x00" * 30,  # success-shaped but major=12, not X11
    b"SSH-2.0-OpenSSH_9.6\r\nblahblahblahblah",         # a wholly different service on the port
])
def test_garbage_or_wrong_protocol_is_refused(raw):
    assert _parse_setup_reply(raw) is None


# ── plugin behaviour ─────────────────────────────────────────────────────────

def _patch_probe(monkeypatch, result=None, exc=None):
    async def fake(self, ip, port):
        if exc is not None:
            raise exc
        return result
    monkeypatch.setattr(X11OpenPlugin, "_probe", fake)


@pytest.mark.asyncio
async def test_open_display_is_reported_critical(monkeypatch):
    _patch_probe(monkeypatch, result=_success(vendor=b"The X.Org Foundation"))
    host = _host([_port(6000)])

    findings = await X11OpenPlugin().check(None, host)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.critical
    assert "Open X11 Display :0" in finding.title
    assert "The X.Org Foundation" in finding.evidence
    assert finding.port_number == 6000
    assert finding.protocol == "tcp"


@pytest.mark.asyncio
async def test_display_number_matches_the_port_offset(monkeypatch):
    _patch_probe(monkeypatch, result=_success())
    host = _host([_port(6003)])

    findings = await X11OpenPlugin().check(None, host)

    assert "display :3" in findings[0].evidence
    assert "Open X11 Display :3" in findings[0].title


@pytest.mark.asyncio
async def test_failed_setup_is_not_reported(monkeypatch):
    """The server demanded MIT-MAGIC-COOKIE-1 and we didn't have one — secure."""
    _patch_probe(monkeypatch, result=_failed(b"No MIT-MAGIC-COOKIE-1 supplied"))
    host = _host([_port(6000)])

    assert await X11OpenPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_authenticate_reply_is_not_reported(monkeypatch):
    _patch_probe(monkeypatch, result=_authenticate())
    host = _host([_port(6000)])

    assert await X11OpenPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_closed_port_is_skipped_without_probing(monkeypatch):
    async def fail_if_called(self, ip, port):
        raise AssertionError("must not probe a closed port")
    monkeypatch.setattr(X11OpenPlugin, "_probe", fail_if_called)
    host = _host([_port(6000, state="closed")])

    assert await X11OpenPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_unreachable_port_produces_no_finding_and_no_exception(monkeypatch):
    _patch_probe(monkeypatch, exc=ConnectionRefusedError())
    host = _host([_port(6000)])

    assert await X11OpenPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_wrong_protocol_reply_produces_no_finding(monkeypatch):
    """Some other service listening on 6000 must never be reported as an X display."""
    _patch_probe(monkeypatch, result=b"220 some-other-service ready\r\n")
    host = _host([_port(6000)])

    assert await X11OpenPlugin().check(None, host) == []


def test_all_six_displays_are_covered():
    assert X11_PORTS == [6000, 6001, 6002, 6003, 6004, 6005]
