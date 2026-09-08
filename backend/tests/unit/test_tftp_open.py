"""TFTP service exposure detection (UDP/69).

Pins the reply classifier (only a well-formed DATA/ERROR/OACK for our own
transfer counts — anything else is refused) and the plugin's deliberate
decision that an ERROR reply to the detection RRQ still proves a TFTP daemon
is listening and answering, so it is reported (medium), same as a DATA reply.
Only a *sensitive* filename actually returning file contents escalates to high.
"""
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services.tftp_open import (
    TftpOpenPlugin,
    _DETECT_FILE,
    _SENSITIVE_FILES,
    _build_rrq,
    _classify,
)


def _data(block: int = 1, payload: bytes = b"x" * 100) -> bytes:
    return b"\x00\x03" + block.to_bytes(2, "big") + payload


def _error(code: int = 1) -> bytes:
    return b"\x00\x05" + code.to_bytes(2, "big") + b"error\x00"


def _port(number, state="open", protocol="udp"):
    return SimpleNamespace(number=number, state=state, protocol=protocol, banner=None, service=None)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


# ── wire format ──────────────────────────────────────────────────────────────

def test_rrq_is_opcode_one_with_nul_terminated_fields():
    rrq = _build_rrq("startup-config")
    assert rrq[:2] == b"\x00\x01"
    assert rrq == b"\x00\x01startup-config\x00octet\x00"


# ── reply classification ─────────────────────────────────────────────────────

def test_classifies_first_data_block():
    assert _classify(_data(1)) == ("data", 1, 100)


def test_data_block_other_than_one_is_not_our_transfer():
    """We only ever ask for block 1; a different block means this isn't our reply."""
    assert _classify(_data(2)) is None


def test_classifies_known_error_codes():
    assert _classify(_error(1)) == ("error", 1, 0)


def test_classifies_oack():
    assert _classify(b"\x00\x06blksize\x00512\x00")[0] == "oack"


@pytest.mark.parametrize("raw", [
    None,
    b"",
    b"\x00",                              # too short
    b"\x00\x05\x00\x63error\x00",         # error code 0x63 is not defined by RFC 1350
    b"\x00\x04\x00\x01",                  # ACK — not a reply we ever expect
    b"random udp garbage that is not tftp at all",
])
def test_garbage_or_wrong_protocol_is_not_classified(raw):
    assert _classify(raw) is None


# ── plugin behaviour ─────────────────────────────────────────────────────────

def _patch_probe(monkeypatch, replies: dict[str, bytes | None] | None = None, exc=None):
    """Fake the per-filename UDP probe. `replies` maps filename -> raw reply."""
    async def fake(self, ip, port, filename):
        if exc is not None:
            raise exc
        return (replies or {}).get(filename)
    monkeypatch.setattr(TftpOpenPlugin, "_probe", fake)


@pytest.mark.asyncio
async def test_sensitive_config_served_is_reported_high(monkeypatch):
    _patch_probe(monkeypatch, {
        _DETECT_FILE: _error(1),
        "startup-config": _data(1, b"enable secret 5 $1$abc\n"),
        "running-config": _error(1),
        "config.text": _error(1),
    })
    host = _host([_port(69)])

    findings = await TftpOpenPlugin().check(None, host)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.title == "TFTP Server Exposes Device Configuration Files"
    assert "startup-config" in finding.evidence
    assert finding.port_number == 69
    assert finding.protocol == "udp"


@pytest.mark.asyncio
async def test_error_reply_to_detect_probe_still_proves_daemon_is_answering(monkeypatch):
    """Pinned behaviour: an ERROR (e.g. file-not-found) to the detection RRQ is
    still treated as proof TFTP is listening — it is reported as medium, not
    dropped as a non-answer."""
    _patch_probe(monkeypatch, {
        _DETECT_FILE: _error(1),
        "startup-config": _error(1),
        "running-config": _error(1),
        "config.text": _error(1),
    })
    host = _host([_port(69)])

    findings = await TftpOpenPlugin().check(None, host)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.medium
    assert finding.title == "TFTP Service Reachable"
    assert "ERROR 1" in finding.evidence
    assert "a TFTP daemon is answering" in finding.evidence


@pytest.mark.asyncio
async def test_data_reply_with_no_sensitive_files_is_reported_medium(monkeypatch):
    _patch_probe(monkeypatch, {
        _DETECT_FILE: _data(1, b"probe response"),
        "startup-config": _error(1),
        "running-config": _error(1),
        "config.text": _error(1),
    })
    host = _host([_port(69)])

    findings = await TftpOpenPlugin().check(None, host)

    assert len(findings) == 1
    assert findings[0].severity is Severity.medium
    assert findings[0].title == "TFTP Service Reachable"


@pytest.mark.asyncio
async def test_closed_port_is_skipped_without_probing(monkeypatch):
    async def fail_if_called(self, ip, port, filename):
        raise AssertionError("must not probe a closed port")
    monkeypatch.setattr(TftpOpenPlugin, "_probe", fail_if_called)
    host = _host([_port(69, state="closed")])

    assert await TftpOpenPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_open_filtered_state_is_still_tested(monkeypatch):
    """nmap usually can't tell open UDP from filtered, so our own probe decides."""
    _patch_probe(monkeypatch, {_DETECT_FILE: _error(1)})
    host = _host([_port(69, state="open|filtered")])

    findings = await TftpOpenPlugin().check(None, host)
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_no_reply_at_all_produces_no_finding(monkeypatch):
    """Nothing answers the detection RRQ — unreachable or not TFTP; either way, silent."""
    _patch_probe(monkeypatch, {_DETECT_FILE: None})
    host = _host([_port(69)])

    assert await TftpOpenPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_probe_exception_produces_no_finding_and_does_not_raise(monkeypatch):
    _patch_probe(monkeypatch, exc=OSError("network unreachable"))
    host = _host([_port(69)])

    assert await TftpOpenPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_wrong_protocol_udp_reply_produces_no_finding(monkeypatch):
    """Some other UDP service (e.g. DNS) answered on 69 — must not be reported as TFTP."""
    _patch_probe(monkeypatch, {_DETECT_FILE: b"\x00\x00\x81\x80" + b"\x00" * 20})
    host = _host([_port(69)])

    assert await TftpOpenPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_tcp_port_69_is_never_probed(monkeypatch):
    """This plugin only speaks UDP; a TCP listener on 69 is out of scope."""
    async def fail_if_called(self, ip, port, filename):
        raise AssertionError("must not probe a TCP port")
    monkeypatch.setattr(TftpOpenPlugin, "_probe", fail_if_called)
    host = _host([_port(69, protocol="tcp")])

    assert await TftpOpenPlugin().check(None, host) == []


def test_sensitive_files_are_the_expected_set():
    assert _SENSITIVE_FILES == ("startup-config", "running-config", "config.text")
