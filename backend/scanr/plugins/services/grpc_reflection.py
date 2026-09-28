"""gRPC server reflection enabled.

gRPC has no equivalent of a URL you can guess. Methods are addressed by their
fully-qualified protobuf names, and the message shapes are compiled into the
client, so an API with reflection disabled is genuinely opaque to anyone without
the ``.proto`` files.

Server reflection removes that. It is a service whose whole purpose is to hand a
caller the complete schema — every service, every method, every message field and
type — so that generic tooling (``grpcurl``, Postman, BloomRPC) can call the API
without any prior knowledge. Left enabled in production it does exactly the same
for an attacker: the internal API surface, including the administrative and
internal-only services that were never meant to be callable from outside, becomes
self-documenting.

It is the gRPC analogue of GraphQL introspection or a published OpenAPI document,
and it is enabled by a single line that is usually added for local development and
never removed.

The check speaks HTTP/2 directly — the ``ListServices`` reflection call is one
request — and reports the service names the server itself returned. No method on
any discovered service is ever called.
"""
from __future__ import annotations

import asyncio
import logging
import re
import ssl
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

GRPC_PORTS = [50051, 50052, 9090, 9091, 8080, 8443, 443, 6565]

_TIMEOUT = 6.0
_READ_LIMIT = 65536
_MAX_FRAMES = 40

_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_FRAME_DATA = 0x0
_FRAME_HEADERS = 0x1
_FRAME_RST_STREAM = 0x3
_FRAME_SETTINGS = 0x4
_FRAME_GOAWAY = 0x7
_FRAME_WINDOW_UPDATE = 0x8

_FLAG_END_STREAM = 0x1
_FLAG_END_HEADERS = 0x4
_FLAG_SETTINGS_ACK = 0x1

_STREAM_ID = 1

# Both reflection service versions; v1alpha is still what most servers register.
REFLECTION_PATHS = (
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
)

# ServerReflectionRequest{ list_services = "" } — field 7, wire type 2, empty.
#   0x3A = (7 << 3) | 2,  0x00 = zero-length string
_LIST_SERVICES_MESSAGE = b"\x3a\x00"

# Fully-qualified protobuf names: at least one dot, identifier segments.
_SERVICE_NAME_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{1,62}(?:\.[A-Za-z_][A-Za-z0-9_]{1,62})+")
_REFLECTION_SERVICES = (
    b"grpc.reflection.v1.ServerReflection",
    b"grpc.reflection.v1alpha.ServerReflection",
)
# Names that are part of gRPC itself rather than the application's API.
_INFRASTRUCTURE_SERVICES = {
    "grpc.reflection.v1.ServerReflection",
    "grpc.reflection.v1alpha.ServerReflection",
    "grpc.health.v1.Health",
    "grpc.channelz.v1.Channelz",
}
_MIN_NAME_LENGTH = 5


@dataclass
class ReflectionResult:
    path: str
    services: list[str] = field(default_factory=list)

    @property
    def application_services(self) -> list[str]:
        return [name for name in self.services if name not in _INFRASTRUCTURE_SERVICES]


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return struct.pack("!I", len(payload))[1:] + bytes([frame_type, flags]) + struct.pack("!I", stream_id) + payload


def hpack_literal(name: str, value: str) -> bytes:
    """One HPACK 'literal header field without indexing — new name' entry.

    Raw (non-Huffman) strings and a never-indexed representation keep the encoder
    stateless, which is all a single request needs and removes any chance of the
    dynamic table drifting out of step with the server.
    """
    encoded_name = name.encode("ascii")
    encoded_value = value.encode("ascii")
    if len(encoded_name) > 126 or len(encoded_value) > 126:
        raise ValueError("header too long for the simple HPACK encoder")
    return (
        b"\x00"
        + bytes([len(encoded_name)]) + encoded_name
        + bytes([len(encoded_value)]) + encoded_value
    )


def build_headers_payload(path: str, authority: str, scheme: str) -> bytes:
    """Request pseudo-headers and the gRPC headers, in the order HTTP/2 requires."""
    return b"".join((
        hpack_literal(":method", "POST"),
        hpack_literal(":scheme", scheme),
        hpack_literal(":path", path),
        hpack_literal(":authority", authority),
        hpack_literal("content-type", "application/grpc"),
        hpack_literal("te", "trailers"),
        hpack_literal("user-agent", "scanr-grpc-probe/1.0"),
    ))


def build_grpc_message(protobuf: bytes = _LIST_SERVICES_MESSAGE) -> bytes:
    """gRPC length-prefixed message: uncompressed flag, 4-byte length, body."""
    return b"\x00" + struct.pack("!I", len(protobuf)) + protobuf


def iter_frames(buffer: bytes):
    """Yield (type, flags, stream_id, payload) for every complete frame."""
    offset = 0
    while offset + 9 <= len(buffer):
        length = int.from_bytes(buffer[offset:offset + 3], "big")
        frame_type = buffer[offset + 3]
        flags = buffer[offset + 4]
        stream_id = struct.unpack("!I", buffer[offset + 5:offset + 9])[0] & 0x7FFFFFFF
        if offset + 9 + length > len(buffer):
            return
        yield frame_type, flags, stream_id, buffer[offset + 9:offset + 9 + length]
        offset += 9 + length


def extract_service_names(payload: bytes) -> list[str]:
    """Service names from a ListServiceResponse's gRPC message body.

    The response is protobuf. Rather than implement a decoder, the length-delimited
    string fields are read out directly — every service name is a dotted
    identifier, which is unambiguous enough to pull from the wire bytes and keeps
    this check free of a protobuf dependency.
    """
    body = payload
    # Strip the gRPC message framing when present.
    if len(body) >= 5 and body[0] in (0, 1):
        declared = struct.unpack("!I", body[1:5])[0]
        if declared and declared <= len(body) - 5:
            body = body[5:5 + declared]
        else:
            body = body[5:]

    names: list[str] = []
    for match in _SERVICE_NAME_RE.findall(body):
        try:
            name = match.decode("ascii")
        except UnicodeDecodeError:
            continue
        if len(name) < _MIN_NAME_LENGTH or name in names:
            continue
        names.append(name)
    return names


def reflection_confirmed(payload: bytes, names: list[str]) -> bool:
    """Only credit reflection when the reply really is a service listing.

    Either the server named its own reflection service — which only the reflection
    response does — or it returned at least one fully-qualified service name in a
    DATA frame on the reflection method. An error reply carries no DATA at all.
    """
    if any(marker in payload for marker in _REFLECTION_SERVICES):
        return True
    return bool(names)


class GrpcReflectionPlugin(PluginBase):
    id = "services.grpc_reflection"
    name = "gRPC Server Reflection Enabled"
    description = (
        "Detect gRPC servers with reflection enabled and enumerate the services "
        "they expose, which publishes the full internal API schema"
    )
    category = PluginCategory.services
    severity = Severity.medium
    ports = GRPC_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in GRPC_PORTS or port.state != "open":
                continue
            result = await self._reflect(host.ip, port.number)
            if result is None:
                continue
            findings.append(self._build_finding(host.ip, port.number, result))
        return findings

    async def _reflect(self, ip: str, port: int) -> ReflectionResult | None:
        # gRPC is usually TLS-wrapped, but plaintext h2c is common inside a mesh,
        # so both are tried.
        for tls in (True, False):
            for path in REFLECTION_PATHS:
                result = await self._call(ip, port, path, tls)
                if result is not None:
                    return result
        return None

    async def _call(
        self, ip: str, port: int, path: str, tls: bool
    ) -> ReflectionResult | None:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                self._open_connection(ip, port, tls), timeout=_TIMEOUT
            )
            scheme = "https" if tls else "http"
            authority = f"{ip}:{port}"

            writer.write(_PREFACE + frame(_FRAME_SETTINGS, 0, 0, b""))
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT)

            # Acknowledge the server's SETTINGS before sending a request, as the
            # protocol requires; some servers refuse the stream otherwise.
            first = await asyncio.wait_for(reader.read(_READ_LIMIT), timeout=_TIMEOUT)
            if not first:
                return None
            if any(kind == _FRAME_SETTINGS and not flags & _FLAG_SETTINGS_ACK
                   for kind, flags, _sid, _payload in iter_frames(first)):
                writer.write(frame(_FRAME_SETTINGS, _FLAG_SETTINGS_ACK, 0, b""))

            writer.write(
                frame(
                    _FRAME_HEADERS,
                    _FLAG_END_HEADERS,
                    _STREAM_ID,
                    build_headers_payload(path, authority, scheme),
                )
            )
            writer.write(
                frame(_FRAME_DATA, _FLAG_END_STREAM, _STREAM_ID, build_grpc_message())
            )
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT)

            return await self._read_response(reader, path)
        except (OSError, asyncio.TimeoutError, ssl.SSLError, struct.error, ValueError) as exc:
            logger.debug("gRPC reflection probe failed %s:%d (%s): %s", ip, port, path, exc)
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError, ssl.SSLError):
                    pass

    async def _read_response(self, reader, path: str) -> ReflectionResult | None:
        buffer = b""
        for _ in range(_MAX_FRAMES):
            try:
                chunk = await asyncio.wait_for(reader.read(_READ_LIMIT), timeout=_TIMEOUT)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buffer += chunk
            for kind, _flags, stream_id, payload in iter_frames(buffer):
                if kind in (_FRAME_GOAWAY, _FRAME_RST_STREAM):
                    return None
                if kind != _FRAME_DATA or stream_id != _STREAM_ID or not payload:
                    continue
                names = extract_service_names(payload)
                if reflection_confirmed(payload, names):
                    return ReflectionResult(path=path, services=names)
            if len(buffer) > _READ_LIMIT * 4:
                break
        return None

    @staticmethod
    async def _open_connection(ip: str, port: int, tls: bool):
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # ALPN h2 is mandatory for HTTP/2 over TLS; without it a server will
            # negotiate HTTP/1.1 and reject the connection preface.
            context.set_alpn_protocols(["h2"])
            return await asyncio.open_connection(ip, port, ssl=context)
        return await asyncio.open_connection(ip, port)

    def _build_finding(
        self, ip: str, port: int, result: ReflectionResult
    ) -> FindingData:
        application = result.application_services
        # Reflection that exposes real application services publishes the API;
        # reflection that only names gRPC's own services still confirms the
        # capability but discloses much less.
        severity = Severity.medium if application else Severity.low

        evidence = [
            f"POST {result.path} to {ip}:{port} over HTTP/2 with a "
            "ServerReflectionRequest{list_services}",
            "Server returned a ListServicesResponse naming:",
            *(f"  {name}" for name in result.services[:40]),
        ]
        if len(result.services) > 40:
            evidence.append(f"  [... {len(result.services) - 40} more]")
        evidence.append("")
        evidence.append(
            "No method on any listed service was called; only the reflection "
            "ListServices request was sent."
        )

        service_sentence = (
            f"{len(application)} application service(s) were listed: "
            + ", ".join(application[:10])
            + ("…" if len(application) > 10 else "")
            + "."
            if application
            else "Only gRPC's own infrastructure services were listed, so the "
            "application's API was not enumerated in this response — but reflection "
            "itself is enabled and a client can request each file descriptor."
        )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="gRPC Server Reflection Enabled",
            description=(
                f"The gRPC server on {ip}:{port} has server reflection enabled and "
                f"answered an unauthenticated ListServices request. {service_sentence}\n\n"
                "Reflection exists so that generic clients can call an API without "
                "compiled stubs. Enabled in production it gives an attacker the same "
                "thing: the complete schema — every service, method, message and field "
                "type — is retrievable, and 'grpcurl -plaintext HOST:PORT list' then "
                "'describe' turns this host into self-documenting API documentation.\n\n"
                "That matters because gRPC's usual obscurity is load-bearing in practice. "
                "Method names cannot be guessed and message shapes cannot be inferred, so "
                "internal and administrative services are frequently exposed on the "
                "assumption that nobody knows they are there. Reflection removes the "
                "assumption while leaving the exposure.\n\n"
                "Reflection is not itself an authorisation flaw: it discloses the schema, "
                "not the data. The risk is that it turns any missing authorisation check "
                "on a method from something an attacker would have to find into something "
                "they can look up."
            ),
            evidence="\n".join(evidence),
            remediation=(
                "Remove the reflection service registration from production builds. It is "
                "one line, usually added for local development:\n"
                "  Go — drop 'reflection.Register(grpcServer)'\n"
                "  Java — remove 'ProtoReflectionService.newInstance()' from the server "
                "builder\n"
                "  Python — remove the 'grpc_reflection.v1alpha.reflection.enable_server_reflection' call\n"
                "  .NET — remove 'AddGrpcReflection()' / 'MapGrpcReflectionService()'\n"
                "  Node — do not add the reflection service to the server\n\n"
                "Gate it on a build flag or an environment check if developers need it "
                "locally, so it cannot reach production by default.\n\n"
                "Then treat the disclosure as already happened and fix what it exposed: "
                "enforce authentication and per-method authorisation on every service, "
                "especially any administrative or internal service in the list above. "
                "Removing reflection hides the schema; it does not protect a method that "
                "was never checking the caller. Where an internal service does not need to "
                "be reachable from this network at all, restrict it there too."
            ),
            references=[
                "https://grpc.io/docs/guides/reflection/",
                "https://github.com/fullstorydev/grpcurl",
                "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=f"grpcurl -plaintext {ip}:{port} list",
        )
