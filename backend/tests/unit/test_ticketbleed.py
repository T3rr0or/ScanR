"""Ticketbleed (CVE-2016-9244) memory disclosure.

Pins the signature: a 32-byte session id that starts with our short marker is
leaked memory; an echoed short id or a fresh random id is not. Both markers must
leak for the plugin to report.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.ssl_tls._handshake import ServerHello
from scanr.plugins.ssl_tls.ticketbleed import (
    MARKERS,
    TicketbleedPlugin,
    leaked_memory,
)


def _port(number=443, state="open", service=None):
    return SimpleNamespace(number=number, state=state, service=service)


def _host(ports, ip="192.0.2.60"):
    return SimpleNamespace(ip=ip, hostname="bigip.example", ports=ports)


# ── leak signature ───────────────────────────────────────────────────────────

def test_full_id_starting_with_marker_is_leaked_memory():
    marker = b"\x41"
    session_id = marker + bytes(range(31))
    leak = leaked_memory(marker, session_id)
    assert leak == bytes(range(31))


def test_echoed_short_id_is_not_a_leak():
    # A healthy server accepting resumption echoes our 1-byte id.
    assert leaked_memory(b"\x41", b"\x41") is None


def test_fresh_random_id_not_starting_with_marker_is_not_a_leak():
    assert leaked_memory(b"\x41", b"\x99" + bytes(range(31))) is None


# ── plugin behaviour ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_both_markers_leaking_is_reported(monkeypatch):
    async def fake_hello(ip, port, hostname, marker):
        return ServerHello(session_id=marker + bytes(range(31)))
    monkeypatch.setattr(TicketbleedPlugin, "_server_hello", staticmethod(fake_hello))
    findings = await TicketbleedPlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].cve_ids == ["CVE-2016-9244"]
    assert findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_one_marker_leaking_is_not_enough(monkeypatch):
    # Second marker echoed (healthy), first leaked — a coincidence, not a leak.
    async def fake_hello(ip, port, hostname, marker):
        if marker == MARKERS[0]:
            return ServerHello(session_id=marker + bytes(range(31)))
        return ServerHello(session_id=marker)   # echoed
    monkeypatch.setattr(TicketbleedPlugin, "_server_hello", staticmethod(fake_hello))
    assert await TicketbleedPlugin().check(None, _host([_port()])) == []


@pytest.mark.asyncio
async def test_healthy_server_is_quiet(monkeypatch):
    async def fake_hello(ip, port, hostname, marker):
        return ServerHello(session_id=b"\x77" + bytes(range(31)))   # fresh id
    monkeypatch.setattr(TicketbleedPlugin, "_server_hello", staticmethod(fake_hello))
    assert await TicketbleedPlugin().check(None, _host([_port()])) == []


@pytest.mark.asyncio
async def test_no_handshake_is_quiet(monkeypatch):
    async def fake_hello(ip, port, hostname, marker):
        return None
    monkeypatch.setattr(TicketbleedPlugin, "_server_hello", staticmethod(fake_hello))
    assert await TicketbleedPlugin().check(None, _host([_port()])) == []
