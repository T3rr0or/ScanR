"""EtherNet/IP (CIP) device identity exposure detection, TCP 44818.

Safety — the exact bytes this plugin puts on the wire
-----------------------------------------------------
Exactly one 24-byte EtherNet/IP encapsulation frame per port, then the socket is
closed::

    63 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

    63 00                     command 0x0063 = List Identity (little-endian)
    00 00                     command-specific data length: 0
    00 00 00 00               session handle 0 (List Identity needs no session)
    00 00 00 00               status 0
    00 00 00 00 00 00 00 00   sender context (unused, zeroed for determinism)
    00 00 00 00               options 0

List Identity is the discovery request ODVA defines for exactly this purpose:
the target answers out of its Identity Object (class 0x01) with vendor, device
type, product code, revision, serial number and product name. It carries no CIP
request path, so no session is registered and no object attribute is written.

Deliberately never sent: RegisterSession (0x0065) and the SendRRData (0x006f) /
SendUnitData (0x0070) frames that carry real CIP explicit messaging — including
Set_Attribute_Single, tag writes and the Identity Object Reset service (0x05),
which would reboot the controller. Nothing is sent to UDP 2222 either: that port
carries CIP class-1 implicit I/O, i.e. the live cyclic process data of a running
machine, and it does not implement List Identity, so probing it would be
unsolicited traffic into an active I/O connection for no diagnostic gain. If
2222 is open on the host it is only mentioned in the evidence. One connection,
one frame, no retry loop.
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

_ENIP_PORT = 44818
_IMPLICIT_IO_PORT = 2222  # CIP class-1 I/O; never probed, only reported if open
_TIMEOUT = 5.0

_CMD_LIST_IDENTITY = 0x0063
_ITEM_CIP_IDENTITY = 0x000C
_ENCAP_HEADER_LEN = 24
_MAX_PAYLOAD = 512  # a List Identity reply is well under 100 bytes

LIST_IDENTITY_REQUEST = struct.pack(
    "<HHII8sI",
    _CMD_LIST_IDENTITY,  # command
    0,                   # command-specific data length
    0,                   # session handle
    0,                   # status
    b"\x00" * 8,         # sender context
    0,                   # options
)

# ODVA assigns vendor IDs; only the one that is unambiguous is named, everything
# else is reported as its number rather than risking a wrong manufacturer.
_VENDORS = {1: "Rockwell Automation/Allen-Bradley"}

# CIP device profile numbers (CIP Vol 1, appendix B). Common profiles only.
_DEVICE_TYPES = {
    0x00: "Generic Device",
    0x02: "AC Drive",
    0x03: "Motor Overload",
    0x04: "Limit Switch",
    0x05: "Inductive Proximity Switch",
    0x06: "Photoelectric Sensor",
    0x07: "General Purpose Discrete I/O",
    0x09: "Resolver",
    0x0C: "Communications Adapter",
    0x0E: "Programmable Logic Controller",
    0x10: "Position Controller",
    0x13: "DC Drive",
    0x15: "Contactor",
    0x16: "Motor Starter",
    0x17: "Soft Start Starter",
    0x18: "Human-Machine Interface",
    0x1B: "Pneumatic Valve",
    0x1C: "Vacuum Pressure Gauge",
    0x2B: "Safety Discrete I/O Device",
}


class EnipDetectPlugin(PluginBase):
    id = "services.enip_detect"
    name = "EtherNet/IP CIP Device Detection"
    description = "Detect exposed EtherNet/IP devices (detection only — single List Identity discovery request)"
    category = PluginCategory.services
    severity = Severity.high
    ports = [_ENIP_PORT, _IMPLICIT_IO_PORT]
    # List Identity reads the Identity Object. No session is registered and no
    # CIP service that could change device state is ever sent.
    destructive = False

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        target = next(
            (
                p for p in host.ports
                if p.number == _ENIP_PORT and p.state == "open" and getattr(p, "protocol", "tcp") != "udp"
            ),
            None,
        )
        if target is None:
            return []

        try:
            response = await self._probe_enip(host.ip, target.number)
        except Exception:
            logger.debug("EtherNet/IP probe failed for %s:%s", host.ip, target.number, exc_info=True)
            return []

        identity = self._parse_list_identity(response) if response else None
        if not identity:
            return []

        io_open = any(
            p.number == _IMPLICIT_IO_PORT and p.state == "open" for p in host.ports
        )
        return [self._make_finding(target.number, identity, io_open)]

    async def _probe_enip(self, ip: str, port: int) -> bytes | None:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=_TIMEOUT)
        try:
            writer.write(LIST_IDENTITY_REQUEST)
            await writer.drain()
            header = await asyncio.wait_for(reader.readexactly(_ENCAP_HEADER_LEN), timeout=_TIMEOUT)
            length = struct.unpack_from("<H", header, 2)[0]
            if length == 0 or length > _MAX_PAYLOAD:
                return header
            payload = await asyncio.wait_for(reader.readexactly(length), timeout=_TIMEOUT)
            return header + payload
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ── parsing ───────────────────────────────────────────────────────────────

    def _parse_list_identity(self, data: bytes | None) -> dict | None:
        """Pull the Identity Object fields out of a List Identity reply.

        Returns None unless the reply really is an EtherNet/IP encapsulation of
        command 0x0063 carrying a CIP Identity item, so a truncated frame or a
        different service on 44818 reports nothing.
        """
        if not data or len(data) < _ENCAP_HEADER_LEN:
            return None
        command, length = struct.unpack_from("<HH", data, 0)
        status = struct.unpack_from("<I", data, 8)[0]
        if command != _CMD_LIST_IDENTITY or status != 0:
            return None

        payload = data[_ENCAP_HEADER_LEN:_ENCAP_HEADER_LEN + length]
        if len(payload) < length or len(payload) < 6:
            return None  # truncated command-specific data

        item_count = struct.unpack_from("<H", payload, 0)[0]
        if item_count < 1:
            return None
        item_type, item_length = struct.unpack_from("<HH", payload, 2)
        if item_type != _ITEM_CIP_IDENTITY:
            return None
        item = payload[6:6 + item_length]
        # version(2) + socket address(16) + vendor(2) + device type(2) +
        # product code(2) + revision(2) + status(2) + serial(4) + name length(1)
        if len(item) < 33:
            return None

        encap_version = struct.unpack_from("<H", item, 0)[0]
        vendor_id, device_type, product_code = struct.unpack_from("<HHH", item, 18)
        revision_major, revision_minor = item[24], item[25]
        device_status, serial = struct.unpack_from("<HI", item, 26)
        name_length = item[32]
        name = item[33:33 + name_length].decode("ascii", errors="ignore").strip()
        if len(item) < 33 + name_length:
            return None  # product name promised more bytes than arrived

        return {
            "encap_version": encap_version,
            "vendor_id": vendor_id,
            "vendor": _VENDORS.get(vendor_id),
            "device_type": device_type,
            "device_type_name": _DEVICE_TYPES.get(device_type),
            "product_code": product_code,
            "revision": f"{revision_major}.{revision_minor}",
            "status": device_status,
            "serial": serial,
            "product_name": name or None,
        }

    def _make_finding(self, port: int, identity: dict, io_open: bool) -> FindingData:
        vendor = identity["vendor"] or f"vendor ID {identity['vendor_id']}"
        device_type = identity["device_type_name"] or f"type 0x{identity['device_type']:04x}"
        evidence_lines = [
            f"Sent EtherNet/IP List Identity (0x0063): {LIST_IDENTITY_REQUEST.hex(' ')}",
            f"Product name: {identity['product_name'] or 'unknown'}",
            f"Vendor: {vendor} (0x{identity['vendor_id']:04x}); device type: {device_type}; "
            f"product code: {identity['product_code']}",
            f"Revision: {identity['revision']}; serial number: 0x{identity['serial']:08x}; "
            f"encapsulation protocol version: {identity['encap_version']}",
        ]
        if io_open:
            evidence_lines.append(
                f"UDP {_IMPLICIT_IO_PORT} (CIP implicit I/O) is also reported open on this host, "
                "which suggests live process data is being exchanged over this network path."
            )
        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="EtherNet/IP CIP Device Exposed",
            description=(
                "An EtherNet/IP device answered a List Identity discovery request with no "
                "credentials and disclosed its vendor, model, firmware revision and serial number. "
                "EtherNet/IP has no authentication: the same TCP 44818 endpoint accepts CIP explicit "
                "messaging, so an attacker on this network can read and write controller tags, "
                "enumerate the configured I/O, and invoke device services such as Identity Object "
                "Reset, which reboots the controller. The disclosed firmware revision also tells an "
                "attacker precisely which vendor advisories apply to this device."
            ),
            evidence="\n".join(evidence_lines),
            remediation=(
                "EtherNet/IP cannot authenticate its peers, so restrict who can reach it: keep TCP "
                "44818 and UDP 2222 inside a dedicated automation cell behind an industrial "
                "firewall, permit them only from the PLCs, HMIs and engineering stations that need "
                "them, and never expose them to the internet or to general corporate VLANs. Where "
                "the platform supports it, enable the controller's own protections (CIP Security, "
                "keyswitch in RUN, trusted-slot/session policies) and use a VPN or jump host for "
                "remote engineering access."
            ),
            references=[
                "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-205a",
                "https://www.odva.org/",
            ],
            port_number=port,
            protocol="tcp",
        )
