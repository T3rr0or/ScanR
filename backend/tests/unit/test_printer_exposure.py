"""Unauthenticated raw print service (PJL) detection.

Pins the PJL reply parser, and specifically that a non-printer banner on 9100 is
not misreported as a printer.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.services.printer_exposure import (
    PrinterExposurePlugin,
    PjlInfo,
    parse_pjl,
)


def _port(number=9100, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.90"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def test_parses_model_status_and_vendor():
    reply = (
        b'@PJL INFO ID\r\n"HP LaserJet MFP M428fdw"\r\n\x0c'
        b'@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY="Ready"\r\n\x0c'
    )
    info = parse_pjl(reply)
    assert info.model == "HP LaserJet MFP M428fdw"
    assert info.vendor == "HP"
    assert info.status_code == "10001"
    assert info.display == "Ready"
    assert info.answered_pjl


def test_bare_model_line_trusted_only_with_a_vendor():
    info = parse_pjl(b"Kyocera ECOSYS M5526cdw\r\n")
    assert info.vendor == "Kyocera" and info.answered_pjl


def test_ssh_banner_is_not_a_printer():
    assert not parse_pjl(b"SSH-2.0-OpenSSH_9.6\r\n").answered_pjl


def test_http_response_is_not_a_printer():
    assert not parse_pjl(b"HTTP/1.1 400 Bad Request\r\n\r\n").answered_pjl


def test_empty_reply_is_not_a_printer():
    assert not parse_pjl(b"").answered_pjl


@pytest.mark.asyncio
async def test_identified_device_reported_medium(monkeypatch):
    async def fake_probe(self, ip, port):
        return PjlInfo(raw="@PJL", model="HP LaserJet", vendor="HP", lines=["@PJL INFO ID"])
    monkeypatch.setattr(PrinterExposurePlugin, "_probe", fake_probe)
    findings = await PrinterExposurePlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert findings[0].port_number == 9100


@pytest.mark.asyncio
async def test_no_pjl_answer_is_silent(monkeypatch):
    async def fake_probe(self, ip, port):
        return PjlInfo()
    monkeypatch.setattr(PrinterExposurePlugin, "_probe", fake_probe)
    assert await PrinterExposurePlugin().check(None, _host([_port()])) == []
