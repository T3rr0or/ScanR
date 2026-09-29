"""Unauthenticated RTSP video stream exposure.

Cameras, NVRs and door-entry systems publish video over RTSP, and the default
configuration on much of that hardware does not require authentication on the
stream itself — the web interface asks for a password, the media port does not.
The result is a live view of a reception area, a server room, a production line
or a car park, readable by anyone who can reach port 554.

The check is the same conversation a media player has: ``OPTIONS`` to confirm an
RTSP server is listening, then ``DESCRIBE`` on the vendor's documented stream
paths. A ``401`` means the stream is protected and nothing is reported. A ``200``
with an SDP body means the server just handed us the stream description — the
media parameters a client needs to start receiving video — without a credential.

No media is ever received: the SDP is read and the connection closed before any
``SETUP``/``PLAY``, so no video session is established and no recording is
triggered.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

RTSP_PORTS = [554, 8554, 10554, 5554, 1554]

_TIMEOUT = 5.0
_READ_LIMIT = 8192
_USER_AGENT = "ScanR/1.0 (authorized security assessment)"

# Documented default stream paths, by vendor. Ordered so the generic ones are
# tried last.
STREAM_PATHS: tuple[str, ...] = (
    "/Streaming/Channels/101",                      # Hikvision
    "/cam/realmonitor?channel=1&subtype=0",         # Dahua
    "/axis-media/media.amp",                        # Axis
    "/videoMain",                                   # Foscam
    "/live/ch00_0",                                 # Various Chinese OEM NVRs
    "/media/video1",                                # ONVIF Profile S common
    "/onvif1",
    "/h264Preview_01_main",                         # Reolink
    "/live.sdp",
    "/live",
    "/stream1",
    "/video",
    "/",
)

_MAX_PATHS = 8

# Server banners that identify the device class.
_VENDOR_HINTS = (
    ("hikvision", "Hikvision"),
    ("dahua", "Dahua"),
    ("axis", "Axis Communications"),
    ("reolink", "Reolink"),
    ("foscam", "Foscam"),
    ("dvrdvs", "Hikvision OEM (DVRDVS)"),
    ("gstreamer", "GStreamer-based server"),
    ("live555", "Live555 media server"),
    ("vivotek", "Vivotek"),
    ("bosch", "Bosch"),
    ("hanwha", "Hanwha / Samsung"),
    ("mobotix", "Mobotix"),
)

_STATUS_RE = re.compile(r"^RTSP/1\.0\s+(\d{3})", re.I)
_SDP_MEDIA_RE = re.compile(r"^m=(video|audio)\s", re.M)


@dataclass
class RtspResponse:
    status: int
    headers: dict[str, str]
    body: str

    @property
    def is_sdp(self) -> bool:
        """True when the body is a session description carrying a media stream."""
        content_type = self.headers.get("content-type", "").lower()
        if "application/sdp" not in content_type and not self.body.startswith("v="):
            return False
        return bool(_SDP_MEDIA_RE.search(self.body))


def build_request(method: str, url: str, cseq: int, extra: dict[str, str] | None = None) -> bytes:
    lines = [f"{method} {url} RTSP/1.0", f"CSeq: {cseq}", f"User-Agent: {_USER_AGENT}"]
    for name, value in (extra or {}).items():
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def parse_response(raw: bytes) -> RtspResponse | None:
    """Parse an RTSP reply. None when the peer did not speak RTSP."""
    if not raw:
        return None
    try:
        text = raw.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return None
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    match = _STATUS_RE.match(lines[0].strip())
    if match is None:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name:
            headers[name.strip().lower()] = value.strip()
    return RtspResponse(status=int(match.group(1)), headers=headers, body=body)


def identify_vendor(server_header: str) -> str:
    lowered = server_header.lower()
    for needle, label in _VENDOR_HINTS:
        if needle in lowered:
            return label
    return ""


class RtspExposurePlugin(PluginBase):
    id = "services.rtsp_exposure"
    name = "RTSP Video Stream Exposure"
    description = (
        "Detect RTSP servers and confirm whether their video streams are "
        "describable without authentication"
    )
    category = PluginCategory.services
    severity = Severity.high
    ports = RTSP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in RTSP_PORTS or port.state != "open":
                continue
            options = await self._options(host.ip, port.number)
            if options is None:
                continue
            open_streams = await self._describe_streams(host.ip, port.number)
            findings.append(
                self._build_finding(host.ip, port.number, options, open_streams)
            )
        return findings

    async def _options(self, ip: str, port: int) -> RtspResponse | None:
        request = build_request("OPTIONS", f"rtsp://{ip}:{port}/", 1)
        raw = await self._exchange(ip, port, request)
        return parse_response(raw)

    async def _describe_streams(
        self, ip: str, port: int
    ) -> list[tuple[str, RtspResponse]]:
        """Paths whose DESCRIBE returned a usable session description."""
        found: list[tuple[str, RtspResponse]] = []
        for index, path in enumerate(STREAM_PATHS[:_MAX_PATHS], start=2):
            url = f"rtsp://{ip}:{port}{path}"
            request = build_request(
                "DESCRIBE", url, index, {"Accept": "application/sdp"}
            )
            raw = await self._exchange(ip, port, request)
            response = parse_response(raw)
            if response is None:
                continue
            if response.status == 200 and response.is_sdp:
                found.append((path, response))
                break  # one confirmed open stream is the finding
        return found

    @staticmethod
    async def _exchange(ip: str, port: int, request: bytes) -> bytes:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=_TIMEOUT
            )
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT)
            return await asyncio.wait_for(reader.read(_READ_LIMIT), timeout=_TIMEOUT)
        except (OSError, asyncio.TimeoutError) as exc:
            logger.debug("RTSP exchange failed %s:%d: %s", ip, port, exc)
            return b""
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError):
                    pass

    def _build_finding(
        self,
        ip: str,
        port: int,
        options: RtspResponse,
        open_streams: list[tuple[str, RtspResponse]],
    ) -> FindingData:
        server = options.headers.get("server", "")
        vendor = identify_vendor(server)
        methods = options.headers.get("public", "")

        if not open_streams:
            return FindingData(
                plugin_id=self.id,
                severity=Severity.low,
                title="RTSP Service Reachable" + (f" ({vendor})" if vendor else ""),
                description=(
                    f"An RTSP server is listening on {ip}:{port}. Every stream path "
                    "tested required authentication, so no video was obtainable "
                    "anonymously.\n\n"
                    "The service is still an authentication surface on a device class "
                    "whose firmware is rarely patched and whose default credentials are "
                    "published. It is reported so the exposure is recorded, not because "
                    "a stream was readable."
                ),
                evidence=(
                    f"OPTIONS rtsp://{ip}:{port}/ → {options.status}\n"
                    + (f"Server: {server}\n" if server else "")
                    + (f"Public: {methods}\n" if methods else "")
                    + f"DESCRIBE tested {min(len(STREAM_PATHS), _MAX_PATHS)} documented "
                    "stream path(s); none returned a session description without "
                    "authentication."
                ),
                remediation=(
                    "Keep RTSP off untrusted networks — put cameras on their own VLAN "
                    "with no route to or from the internet, and reach them through a VMS "
                    "or VPN. Confirm the device's credentials have been changed from the "
                    "vendor default, and that its firmware is current."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc7826",
                    "https://attack.mitre.org/techniques/T1125/",
                ],
                port_number=port,
                protocol="tcp",
                peer_review_command=f"curl -s rtsp://{ip}:{port}/ -X OPTIONS",
            )

        path, response = open_streams[0]
        media = _SDP_MEDIA_RE.findall(response.body)
        session_name = ""
        for line in response.body.splitlines():
            if line.startswith("s="):
                session_name = line[2:].strip()
                break

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title=(
                "Unauthenticated RTSP Video Stream Accessible"
                + (f" ({vendor})" if vendor else "")
            ),
            description=(
                f"The RTSP server on {ip}:{port} returned a full session description for "
                f"{path} without any credential. Anyone who can reach this port can open "
                "the stream in a standard media player.\n\n"
                "For a camera or NVR this is a direct physical-security failure: live "
                "video of whatever the device watches, available to anyone on the "
                "network. It is also useful to an attacker beyond the images themselves "
                "— a view of a reception desk, a badge reader, a whiteboard or an "
                "operator's screen supports social engineering and, quite often, reveals "
                "credentials directly.\n\n"
                "Cameras are frequently the least-managed devices on a network. An "
                "unauthenticated stream usually means the device still has its default "
                "administrative password too, which makes it a foothold as well as a "
                "privacy problem."
            ),
            evidence=(
                f"OPTIONS rtsp://{ip}:{port}/ → {options.status}\n"
                + (f"Server: {server}\n" if server else "")
                + (f"Public: {methods}\n" if methods else "")
                + f"DESCRIBE rtsp://{ip}:{port}{path} → {response.status} "
                f"({response.headers.get('content-type', 'no content-type')})\n"
                + (f"Session name (SDP s=): {session_name}\n" if session_name else "")
                + f"Media streams described: {', '.join(media) or 'none named'}\n"
                + "SDP body (truncated):\n"
                + "\n".join(f"  {line}" for line in response.body.splitlines()[:12])
                + "\n\nNo SETUP or PLAY was sent, so no media session was established."
            ),
            remediation=(
                "Require authentication on the media port, not only on the web "
                "interface. On Hikvision and Dahua hardware this is a separate setting "
                "from the admin password and is commonly left open; enable it "
                "explicitly and verify with a DESCRIBE.\n\n"
                "Then treat the network as the real control: put cameras and NVRs on an "
                "isolated VLAN with no inbound path from user networks and no outbound "
                "internet access, and expose video only through the VMS. Disable UPnP on "
                "the device so it cannot open its own port on the firewall — that is how "
                "most publicly-reachable cameras got there.\n\n"
                "Change the administrative credentials and update the firmware while you "
                "are in the interface. If the stream was reachable from the internet, "
                "assume the footage has been viewed and handle it as a privacy incident: "
                "in the EU this is personal data under the GDPR and may be notifiable."
            ),
            references=[
                "https://datatracker.ietf.org/doc/html/rfc7826",
                "https://attack.mitre.org/techniques/T1125/",
                "https://www.cisa.gov/news-events/news/securing-network-connected-cameras",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=f"ffprobe -rtsp_transport tcp rtsp://{ip}:{port}{path}",
        )
