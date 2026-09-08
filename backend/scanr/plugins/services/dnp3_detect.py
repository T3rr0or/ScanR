"""DNP3 (IEEE 1815, TCP 20000) outstation exposure detection.

Safety — the exact bytes this plugin puts on the wire
-----------------------------------------------------
Exactly one 10-byte DNP3 link-layer frame per port, then the socket is closed::

    05 64 05 c9 00 00 00 00 36 4c

    05 64   start bytes
    05      length: CONTROL + DESTINATION + SOURCE, no user data
    c9      control: DIR=1 (master->outstation), PRM=1 (primary), FCB=0, FCV=0,
            function code 9 = REQUEST LINK STATUS
    00 00   destination link address 0
    00 00   source link address 0
    36 4c   CRC-16/DNP over the 8 preceding bytes, low byte first

REQUEST LINK STATUS is a data-link-layer keep-alive: it asks the outstation
whether its link is up. It carries no transport segment and no application
fragment at all, so it cannot read a point, cannot select or operate an output,
and cannot restart anything. The frame is CRC-correct by construction, because
malformed DNP3 framing — not well-formed requests — is what has historically
wedged outstations.

Deliberately never sent: any application-layer function, in particular
SELECT (0x03), OPERATE (0x04), DIRECT OPERATE (0x05/0x06), COLD/WARM RESTART
(0x0d/0x0e) and WRITE (0x02). There is no retry loop and, importantly, no sweep
of the 65 536 possible link addresses: a device configured with a link address
other than 0 simply will not answer and is reported as not detected. Walking the
address space would be far more traffic than any identification is worth.
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

_START_BYTES = b"\x05\x64"
_TIMEOUT = 5.0
_HEADER_LEN = 10  # start(2) + length(1) + control(1) + dest(2) + src(2) + crc(2)

# Secondary-station link function codes that a live outstation may answer with.
_LINK_STATUS = 0x0B  # requested status of link
_ACK = 0x00
_NACK = 0x01
_NOT_SUPPORTED = 0x0F
_SECONDARY_FUNCTIONS = {_ACK, _NACK, _LINK_STATUS, _NOT_SUPPORTED}


def _dnp3_crc(data: bytes) -> int:
    """CRC-16/DNP (poly 0x3d65 reflected, init 0x0000, final XOR 0xffff)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def _build_link_status_request(destination: int = 0, source: int = 0) -> bytes:
    header = struct.pack("<BBBBHH", 0x05, 0x64, 0x05, 0xC9, destination, source)
    return header + struct.pack("<H", _dnp3_crc(header))


LINK_STATUS_REQUEST = _build_link_status_request()


class Dnp3DetectPlugin(PluginBase):
    id = "services.dnp3_detect"
    name = "DNP3 SCADA Outstation Detection"
    description = "Detect exposed DNP3 outstations (detection only — single link-layer status request, no application data)"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [20000]
    # A link-status request never reaches the application layer, so no point can
    # be read and no control command can be issued by this plugin.
    destructive = False

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number != 20000 or port.state != "open":
                continue
            if getattr(port, "protocol", "tcp") == "udp":
                continue  # DNP3 over UDP exists but this probe is the TCP framing
            try:
                response = await self._probe_dnp3(host.ip, port.number)
            except Exception:
                logger.debug("DNP3 probe failed for %s:%s", host.ip, port.number, exc_info=True)
                continue
            parsed = self._parse_link_response(response) if response else None
            if parsed:
                findings.append(self._make_finding(port.number, parsed))
        return findings

    async def _probe_dnp3(self, ip: str, port: int) -> bytes | None:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=_TIMEOUT)
        try:
            writer.write(LINK_STATUS_REQUEST)
            await writer.drain()
            # A link-status reply is a single 10-byte frame; 64 is room to spare.
            return await asyncio.wait_for(reader.read(64), timeout=_TIMEOUT)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ── parsing ───────────────────────────────────────────────────────────────

    def _parse_link_response(self, data: bytes | None) -> dict | None:
        """Validate a DNP3 link-layer reply and pull the outstation address out.

        The header CRC is checked, not just the start bytes: that is what keeps a
        banner from some other service on 20000 from being reported as DNP3.
        """
        if not data or len(data) < _HEADER_LEN:
            return None
        if data[:2] != _START_BYTES:
            return None
        header = data[:8]
        crc = struct.unpack_from("<H", data, 8)[0]
        if crc != _dnp3_crc(header):
            return None

        control = data[3]
        # A reply comes from the secondary station: DIR may be either way round on
        # a TCP link, but PRM (0x40) must be clear on a response.
        if control & 0x40:
            return None
        function = control & 0x0F
        if function not in _SECONDARY_FUNCTIONS:
            return None

        destination, source = struct.unpack_from("<HH", data, 4)
        return {
            "source": source,
            "destination": destination,
            "function": function,
            "control": control,
            "length": data[2],
        }

    def _make_finding(self, port: int, parsed: dict) -> FindingData:
        function_names = {
            _ACK: "ACK",
            _NACK: "NACK",
            _LINK_STATUS: "STATUS OF LINK",
            _NOT_SUPPORTED: "NOT SUPPORTED",
        }
        function = function_names.get(parsed["function"], f"0x{parsed['function']:02x}")
        evidence_lines = [
            f"Sent DNP3 REQUEST LINK STATUS: {LINK_STATUS_REQUEST.hex(' ')}",
            f"Outstation replied with a valid DNP3 frame (control 0x{parsed['control']:02x}, function {function}).",
            f"Outstation (source) link address: {parsed['source']}; frame addressed to {parsed['destination']}.",
        ]
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="DNP3 SCADA Outstation Exposed",
            description=(
                "A DNP3 outstation answered a link-layer status request with no credentials. "
                "DNP3 is used to supervise and control electricity, water and gas infrastructure. "
                "Without DNP3 Secure Authentication (DNP3-SA, IEEE 1815 chapter 7) the protocol has "
                "no notion of an authenticated peer, so anyone who can reach TCP 20000 can not only "
                "poll process state but also issue SELECT/OPERATE control commands to breakers, "
                "valves and setpoints, and send cold restarts — the outstation cannot tell those "
                "requests apart from its real master."
            ),
            evidence="\n".join(evidence_lines),
            remediation=(
                "Treat reachability of TCP 20000 as the control itself: keep DNP3 off routable and "
                "internet-facing paths, and allow it only between the master station and its "
                "outstations through an industrial firewall with an explicit source allow-list. "
                "Where the outstation supports it, enable DNP3 Secure Authentication (IEEE 1815 "
                "chapter 7) or carry DNP3 inside TLS. Remote engineering access should terminate on "
                "a VPN or jump host inside the OT network, never on the outstation itself."
            ),
            references=[
                "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-205a",
                "https://www.dnp.org/",
            ],
            port_number=port,
            protocol="tcp",
        )
