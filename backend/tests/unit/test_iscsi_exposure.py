"""Unauthenticated iSCSI target exposure.

Pins the login/text PDU construction (no credentials, empty update) and the
response parsing that separates an accepted discovery session from a refused one.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.services.iscsi_exposure import (
    DiscoveredTargets,
    IscsiExposurePlugin,
    LoginResult,
    build_login_request,
    build_sendtargets_request,
    parse_login_response,
    parse_text_response,
)


def _port(number=3260, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.100"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def _login_response(status_class, status_detail, data=b""):
    h = bytearray(48)
    h[0] = 0x23                                   # Login Response opcode
    h[5:8] = len(data).to_bytes(3, "big")
    h[36] = status_class
    h[37] = status_detail
    return bytes(h) + data + b"\x00" * (-len(data) % 4)


def test_login_request_is_a_discovery_session_with_no_auth():
    req = build_login_request()
    assert req[0] & 0x3F == 0x03                  # Login Request opcode
    assert b"SessionType=Discovery" in req
    assert b"AuthMethod=None" in req
    assert len(req) % 4 == 0                      # padded


def test_sendtargets_request_asks_for_all():
    req = build_sendtargets_request()
    assert req[0] & 0x3F == 0x04                  # Text Request opcode
    assert b"SendTargets=All" in req


def test_successful_login_is_parsed():
    result = parse_login_response(_login_response(0, 0))
    assert result.succeeded


def test_auth_failure_login_is_not_success():
    result = parse_login_response(_login_response(2, 1))
    assert not result.succeeded
    assert "Authentication failure" in result.describe()


def test_non_iscsi_reply_is_none():
    assert parse_login_response(b"SSH-2.0-x" + b"\x00" * 48) is None
    assert parse_login_response(b"\x00" * 10) is None


def test_text_response_extracts_targets():
    data = (
        b"TargetName=iqn.2003-01.org.linux-iscsi.vm:datastore1\x00"
        b"TargetAddress=10.0.0.5:3260,1\x00"
    )
    h = bytearray(48)
    h[0] = 0x24
    h[5:8] = len(data).to_bytes(3, "big")
    targets = parse_text_response(bytes(h) + data)
    assert targets.names == ["iqn.2003-01.org.linux-iscsi.vm:datastore1"]
    assert targets.addresses == ["10.0.0.5:3260,1"]


@pytest.mark.asyncio
async def test_unauth_discovery_with_targets_is_critical(monkeypatch):
    async def fake_discover(self, ip, port):
        return LoginResult(0, 0), DiscoveredTargets(names=["iqn.x:vol1"], addresses=[])
    monkeypatch.setattr(IscsiExposurePlugin, "_discover", fake_discover)
    findings = await IscsiExposurePlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


@pytest.mark.asyncio
async def test_authenticated_portal_is_info(monkeypatch):
    async def fake_discover(self, ip, port):
        return LoginResult(2, 1), None            # refused, needs auth
    monkeypatch.setattr(IscsiExposurePlugin, "_discover", fake_discover)
    findings = await IscsiExposurePlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].severity.value == "info"


@pytest.mark.asyncio
async def test_non_iscsi_service_is_silent(monkeypatch):
    async def fake_discover(self, ip, port):
        return None
    monkeypatch.setattr(IscsiExposurePlugin, "_discover", fake_discover)
    assert await IscsiExposurePlugin().check(None, _host([_port()])) == []
