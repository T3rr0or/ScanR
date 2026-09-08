"""TFTP service exposure detection (UDP/69).

TFTP has no authentication mechanism at all — not weak auth, none. The RFC 1350
protocol is four opcodes and a filename, so the finding here is not "auth is
misconfigured" but "a protocol with no auth is reachable". Anyone who can send a
UDP packet to this port can read any file the daemon's root allows, and if the
daemon permits writes (WRQ) they can replace it. TFTP is normally only present
because a switch, phone, or PXE client needs it, and it is meant to live on an
isolated provisioning VLAN.

Two things are probed, both read-only:
  * an RRQ for a filename that will not exist, to prove a TFTP daemon is really
    listening (a DATA *or* an ERROR reply both prove that);
  * an RRQ for a small set of well-known device-config filenames, to tell an
    exposed-but-empty daemon apart from one actually serving switch configs.

We never ACK a DATA block, so the transfer stops after the server's first
packet, and we deliberately record only the byte count of that block — never its
contents — so a retrieved config never lands in the findings database.
We never send a WRQ.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

TFTP_PORT = 69

OP_DATA = 3
OP_ERROR = 5
OP_OACK = 6

_ERROR_MESSAGES = {
    0: "Not defined",
    1: "File not found",
    2: "Access violation",
    3: "Disk full or allocation exceeded",
    4: "Illegal TFTP operation",
    5: "Unknown transfer ID",
    6: "File already exists",
    7: "No such user",
}

# A name no real deployment will hold; its purpose is to make the daemon answer.
_DETECT_FILE = "scanr-tftp-probe.txt"
# Filenames network gear is routinely (mis)configured to serve unauthenticated.
_SENSITIVE_FILES = ("startup-config", "running-config", "config.text")

# UDP is scanned rarely and nmap usually cannot distinguish a silent open UDP
# port from a filtered one, so it reports "open|filtered". Insisting on "open"
# here would make this plugin fire almost never; our own probe is the real
# confirmation, so we accept both and let a non-answer decide.
_TESTABLE_STATES = {"open", "open|filtered"}


def _build_rrq(filename: str, mode: str = "octet") -> bytes:
    """RFC 1350 Read Request: opcode 1, NUL-terminated filename and mode."""
    return (
        struct.pack(">H", 1)
        + filename.encode("ascii", "ignore") + b"\x00"
        + mode.encode("ascii") + b"\x00"
    )


def _classify(raw: bytes | None) -> tuple[str, int, int] | None:
    """Classify one reply as ('data'|'error'|'oack', code, payload length).

    Returns None for anything that is not a well-formed TFTP reply, which is
    what stops an unrelated UDP service from being reported as TFTP.
    """
    if not raw or len(raw) < 4:
        return None
    opcode = struct.unpack(">H", raw[:2])[0]
    if opcode == OP_DATA:
        block = struct.unpack(">H", raw[2:4])[0]
        # A read always starts at block 1; anything else is not our transfer.
        if block != 1:
            return None
        return "data", block, len(raw) - 4
    if opcode == OP_ERROR:
        code = struct.unpack(">H", raw[2:4])[0]
        if code not in _ERROR_MESSAGES:
            return None
        return "error", code, 0
    if opcode == OP_OACK:
        return "oack", 0, len(raw) - 2
    return None


class _TftpProtocol(asyncio.DatagramProtocol):
    """Captures the first datagram received, from whatever source port."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self._future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:  # type: ignore[override]
        if not self._future.done():
            self._future.set_exception(exc)

    def received(self) -> "asyncio.Future[bytes]":
        return self._future


class TftpOpenPlugin(PluginBase):
    id = "services.tftp_open"
    name = "TFTP Service Exposed"
    description = "Detect reachable TFTP daemons, which have no authentication by design"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [TFTP_PORT]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number != TFTP_PORT:
                continue
            if getattr(port, "protocol", "udp") == "tcp":
                continue
            if port.state not in _TESTABLE_STATES:
                continue
            replies: dict[str, bytes | None] = {}
            try:
                for filename in (_DETECT_FILE, *_SENSITIVE_FILES):
                    replies[filename] = await self._probe(host.ip, port.number, filename)
                    if filename == _DETECT_FILE and _classify(replies[filename]) is None:
                        # Nothing that speaks TFTP answered; don't keep poking.
                        break
            except Exception:
                logger.debug("tftp_open: probe failed for %s:%d", host.ip, port.number, exc_info=True)
                continue
            finding = self._analyze(host.ip, port.number, replies)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, ip: str, port: int, filename: str) -> bytes | None:
        """Send one RRQ and return the first datagram, or None on timeout."""
        loop = asyncio.get_running_loop()
        transport = None
        try:
            # Deliberately unconnected (no remote_addr): a TFTP server answers
            # from a freshly allocated transfer ID, not from port 69, and a
            # connected UDP socket would have the kernel drop that reply.
            transport, proto = await loop.create_datagram_endpoint(
                _TftpProtocol, local_addr=("0.0.0.0", 0)
            )
            transport.sendto(_build_rrq(filename), (ip, port))
            try:
                return await asyncio.wait_for(proto.received(), timeout=4.0)
            except (asyncio.TimeoutError, OSError):
                return None
        except OSError:
            return None
        finally:
            if transport is not None:
                transport.close()

    def _analyze(
        self, ip: str, port: int, replies: dict[str, bytes | None]
    ) -> FindingData | None:
        detect = _classify(replies.get(_DETECT_FILE))
        if detect is None:
            # No TFTP reply to the detection RRQ — either nothing is listening or
            # it is not TFTP. Either way, no finding.
            return None

        readable: list[tuple[str, int]] = []
        for filename in _SENSITIVE_FILES:
            parsed = _classify(replies.get(filename))
            if parsed and parsed[0] == "data":
                readable.append((filename, parsed[2]))

        evidence_parts = []
        if detect[0] == "error":
            evidence_parts.append(
                f"RRQ '{_DETECT_FILE}' -> ERROR {detect[1]} ({_ERROR_MESSAGES[detect[1]]}) "
                f"from {ip}:{port} — a TFTP daemon is answering"
            )
        else:
            evidence_parts.append(
                f"RRQ '{_DETECT_FILE}' -> {detect[0].upper()} from {ip}:{port} — "
                "a TFTP daemon is answering"
            )
        for filename, size in readable:
            evidence_parts.append(
                f"RRQ '{filename}' -> DATA block 1, {size} bytes (transfer aborted, contents discarded)"
            )

        if readable:
            severity = Severity.high
            title = "TFTP Server Exposes Device Configuration Files"
            impact = (
                "The daemon served device configuration file(s) to an unauthenticated "
                "request. Switch and router configurations carry SNMP community strings, "
                "RADIUS/TACACS+ shared secrets, VPN pre-shared keys and reversible type-7 "
                "enable passwords, so this is a direct path to administrative control of "
                "the network devices concerned."
            )
        else:
            severity = Severity.medium
            title = "TFTP Service Reachable"
            impact = (
                "No well-known configuration filename was served, but TFTP offers no way "
                "to require credentials, so every file inside the daemon's root is "
                "readable to anyone who can guess or brute-force its name — and if write "
                "requests are permitted, replaceable. TFTP is also frequently used to "
                "stage payloads onto compromised network devices."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=title,
            description=(
                f"A TFTP daemon is reachable on UDP port {port}. TFTP (RFC 1350) has no "
                "authentication, no authorisation and no transport encryption of any kind — "
                f"exposure is the vulnerability. {impact}"
            ),
            evidence="; ".join(evidence_parts),
            remediation=(
                "Restrict UDP port 69 to the provisioning VLAN or the specific device "
                "addresses that need it; TFTP must never be reachable from a user network "
                "or the internet. "
                "Serve only the files required, from a dedicated root directory, and run "
                "the daemon read-only (for example tftpd-hpa without --create). "
                "Remove device configuration backups from the TFTP root and move them to an "
                "authenticated transport such as SCP or SFTP. "
                "Where the daemon only exists for a one-off provisioning task, stop it once "
                "the task is done."
            ),
            references=[
                "https://datatracker.ietf.org/doc/html/rfc1350",
                "https://cwe.mitre.org/data/definitions/306.html",
            ],
            port_number=port,
            protocol="udp",
        )
