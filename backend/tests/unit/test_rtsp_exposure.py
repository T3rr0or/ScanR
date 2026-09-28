"""RTSP video stream exposure.

Pins the RTSP request/response wire handling and the SDP detection that separates
an open stream from a protected one.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.services.rtsp_exposure import (
    RtspExposurePlugin,
    RtspResponse,
    build_request,
    identify_vendor,
    parse_response,
)


def _port(number=554, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.80"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def test_request_is_well_formed():
    req = build_request("OPTIONS", "rtsp://1.2.3.4:554/", 1).decode()
    assert req.startswith("OPTIONS rtsp://1.2.3.4:554/ RTSP/1.0\r\n")
    assert "CSeq: 1" in req


def test_parse_sdp_response_is_a_stream():
    raw = (
        b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n"
        b"Server: Hikvision\r\n\r\nv=0\r\nm=video 0 RTP/AVP 96\r\n"
    )
    r = parse_response(raw)
    assert r.status == 200 and r.is_sdp
    assert identify_vendor(r.headers.get("server", "")) == "Hikvision"


def test_401_is_not_an_open_stream():
    r = parse_response(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n")
    assert r.status == 401 and not r.is_sdp


def test_sdp_without_media_is_not_a_stream():
    r = parse_response(b"RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n")
    assert not r.is_sdp


def test_non_rtsp_reply_is_none():
    assert parse_response(b"HTTP/1.1 200 OK\r\n\r\n") is None
    assert parse_response(b"") is None


@pytest.mark.asyncio
async def test_open_stream_reported_high(monkeypatch):
    async def fake_options(self, ip, port):
        return RtspResponse(200, {"server": "Hikvision", "public": "OPTIONS, DESCRIBE"}, "")
    async def fake_streams(self, ip, port):
        return [("/Streaming/Channels/101",
                 RtspResponse(200, {"content-type": "application/sdp"},
                              "v=0\r\ns=Live\r\nm=video 0 RTP/AVP 96\r\n"))]
    monkeypatch.setattr(RtspExposurePlugin, "_options", fake_options)
    monkeypatch.setattr(RtspExposurePlugin, "_describe_streams", fake_streams)
    findings = await RtspExposurePlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_protected_streams_reported_low(monkeypatch):
    async def fake_options(self, ip, port):
        return RtspResponse(200, {"server": "Dahua"}, "")
    async def fake_streams(self, ip, port):
        return []
    monkeypatch.setattr(RtspExposurePlugin, "_options", fake_options)
    monkeypatch.setattr(RtspExposurePlugin, "_describe_streams", fake_streams)
    findings = await RtspExposurePlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].severity.value == "low"


@pytest.mark.asyncio
async def test_no_rtsp_server_is_silent(monkeypatch):
    async def fake_options(self, ip, port):
        return None
    monkeypatch.setattr(RtspExposurePlugin, "_options", fake_options)
    assert await RtspExposurePlugin().check(None, _host([_port()])) == []
