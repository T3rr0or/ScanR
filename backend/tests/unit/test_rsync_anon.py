"""rsync daemon anonymous module access detection.

Pins module-list parsing (only a real ``@RSYNCD:`` greeting is trusted),
per-module openness classification (``OK`` = open, ``AUTH REQUIRED`` =
challenged, anything else = unknown), and that the plugin only reports modules
it actually entered without a challenge.
"""
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services.rsync_anon import (
    RsyncAnonPlugin,
    _module_is_open,
    _parse_module_list,
)


def _port(number, state="open"):
    return SimpleNamespace(number=number, state=state, banner=None, service=None)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


# ── module list parsing ──────────────────────────────────────────────────────

def test_parses_names_and_comments():
    raw = b"@RSYNCD: 30.0\nbackup\tNightly backups\nhome\n@RSYNCD: EXIT\n"
    assert _parse_module_list(raw) == [("backup", "Nightly backups"), ("home", "")]


def test_empty_listing_is_no_modules():
    assert _parse_module_list(b"@RSYNCD: 30.0\n@RSYNCD: EXIT\n") == []


@pytest.mark.parametrize("raw", [
    None,
    b"",
    b"SSH-2.0-OpenSSH_9.6\r\n",          # a completely different daemon on 873
    b"\x00\x01\x02\x03random binary",     # garbage
])
def test_non_rsync_reply_yields_no_modules(raw):
    """Anything without the @RSYNCD: greeting must never be parsed as a module list."""
    assert _parse_module_list(raw) == []


# ── per-module challenge classification ──────────────────────────────────────

def test_ok_reply_means_open():
    assert _module_is_open(b"@RSYNCD: OK\n") is True


def test_auth_required_reply_means_challenged():
    assert _module_is_open(b"@RSYNCD: AUTH REQUIRED backup\n") is False


@pytest.mark.parametrize("raw", [None, b"", b"garbage\n", b"@RSYNCD: EXIT\n"])
def test_unrecognised_reply_is_unknown(raw):
    assert _module_is_open(raw) is None


# ── plugin behaviour ─────────────────────────────────────────────────────────

def _patch_probe(monkeypatch, result=None, exc=None):
    async def fake(self, ip, port):
        if exc is not None:
            raise exc
        return result
    monkeypatch.setattr(RsyncAnonPlugin, "_probe", fake)


@pytest.mark.asyncio
async def test_open_module_is_reported_high(monkeypatch):
    listing = b"@RSYNCD: 30.0\nbackup\tNightly backups\n@RSYNCD: EXIT\n"
    _patch_probe(monkeypatch, result=(listing, {"backup": b"@RSYNCD: OK\n"}))
    host = _host([_port(873)])

    findings = await RsyncAnonPlugin().check(None, host)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.title == "rsync Daemon Exports Modules Without Authentication"
    assert "backup" in finding.evidence
    assert "@RSYNCD: OK" in finding.evidence
    assert finding.port_number == 873
    assert finding.protocol == "tcp"


@pytest.mark.asyncio
async def test_challenged_module_is_not_reported(monkeypatch):
    """Every module demands auth — the daemon is correctly locked down."""
    listing = b"@RSYNCD: 30.0\nbackup\tNightly backups\n@RSYNCD: EXIT\n"
    _patch_probe(monkeypatch, result=(listing, {"backup": b"@RSYNCD: AUTH REQUIRED backup\n"}))
    host = _host([_port(873)])

    assert await RsyncAnonPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_mixed_modules_report_only_the_open_ones(monkeypatch):
    listing = b"@RSYNCD: 30.0\npublic\nprivate\tRestricted\n@RSYNCD: EXIT\n"
    _patch_probe(monkeypatch, result=(
        listing,
        {"public": b"@RSYNCD: OK\n", "private": b"@RSYNCD: AUTH REQUIRED private\n"},
    ))
    host = _host([_port(873)])

    findings = await RsyncAnonPlugin().check(None, host)

    assert len(findings) == 1
    assert "public" in findings[0].evidence
    assert "private" not in findings[0].evidence


@pytest.mark.asyncio
async def test_closed_port_is_skipped_without_probing(monkeypatch):
    async def fail_if_called(self, ip, port):
        raise AssertionError("must not probe a closed port")
    monkeypatch.setattr(RsyncAnonPlugin, "_probe", fail_if_called)
    host = _host([_port(873, state="closed")])

    assert await RsyncAnonPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_unreachable_port_produces_no_finding_and_no_exception(monkeypatch):
    _patch_probe(monkeypatch, exc=ConnectionRefusedError())
    host = _host([_port(873)])

    assert await RsyncAnonPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_no_greeting_at_all_produces_no_finding(monkeypatch):
    _patch_probe(monkeypatch, result=None)
    host = _host([_port(873)])

    assert await RsyncAnonPlugin().check(None, host) == []


@pytest.mark.asyncio
async def test_wrong_protocol_on_port_873_produces_no_finding(monkeypatch):
    """Some other service answered on 873 — never report it as an rsync daemon."""
    _patch_probe(monkeypatch, result=(b"220 ftp.example.com FTP server ready\r\n", {}))
    host = _host([_port(873)])

    assert await RsyncAnonPlugin().check(None, host) == []
