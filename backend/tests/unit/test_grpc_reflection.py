"""gRPC server reflection detection.

Pins the HTTP/2 framing helpers, the service-name extraction from a
ListServicesResponse, and the confirmation that distinguishes a real listing from
an error frame.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.services.grpc_reflection import (
    GrpcReflectionPlugin,
    ReflectionResult,
    build_grpc_message,
    build_headers_payload,
    extract_service_names,
    frame,
    hpack_literal,
    iter_frames,
    reflection_confirmed,
)


def _port(number=50051, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.110"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def _list_services_message(names):
    inner = b"".join(b"\x0a" + bytes([len(n)]) + n for n in names)
    body = b"\x32" + bytes([len(inner)]) + inner    # field 6, length-delimited
    return build_grpc_message(body)


def test_frame_header_encodes_length_type_flags_stream():
    f = frame(0x1, 0x4, 1, b"abc")
    assert int.from_bytes(f[:3], "big") == 3
    assert f[3] == 0x1 and f[4] == 0x4


def test_hpack_literal_roundtrips_name_and_value():
    encoded = hpack_literal(":method", "POST")
    assert b":method" in encoded and b"POST" in encoded


def test_headers_payload_includes_grpc_content_type():
    payload = build_headers_payload("/x.Y/Z", "h:1", "http")
    assert b"application/grpc" in payload


def test_extract_service_names_reads_dotted_identifiers():
    names = [b"grpc.reflection.v1alpha.ServerReflection", b"myapp.admin.AdminService"]
    got = extract_service_names(_list_services_message(names))
    assert "myapp.admin.AdminService" in got


def test_reflection_confirmed_by_reflection_service_marker():
    payload = _list_services_message([b"grpc.reflection.v1alpha.ServerReflection"])
    assert reflection_confirmed(payload, extract_service_names(payload))


def test_reflection_not_confirmed_on_empty_frame():
    assert not reflection_confirmed(b"", [])


def test_iter_frames_walks_multiple_frames():
    buffer = frame(0x1, 0x4, 1, b"aa") + frame(0x0, 0x1, 1, b"bbbb")
    kinds = [k for k, _fl, _s, _p in iter_frames(buffer)]
    assert kinds == [0x1, 0x0]


def test_application_services_excludes_infrastructure():
    result = ReflectionResult(
        path="/p",
        services=["grpc.reflection.v1alpha.ServerReflection", "grpc.health.v1.Health",
                  "myapp.v1.Users"],
    )
    assert result.application_services == ["myapp.v1.Users"]


@pytest.mark.asyncio
async def test_reflection_with_app_services_is_medium(monkeypatch):
    async def fake_reflect(self, ip, port):
        return ReflectionResult(path="/p", services=["myapp.v1.Users"])
    monkeypatch.setattr(GrpcReflectionPlugin, "_reflect", fake_reflect)
    findings = await GrpcReflectionPlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"


@pytest.mark.asyncio
async def test_no_reflection_is_silent(monkeypatch):
    async def fake_reflect(self, ip, port):
        return None
    monkeypatch.setattr(GrpcReflectionPlugin, "_reflect", fake_reflect)
    assert await GrpcReflectionPlugin().check(None, _host([_port()])) == []
