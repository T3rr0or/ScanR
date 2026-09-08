"""Siemens S7comm (ISO-TSAP / RFC 1006, TCP 102) exposure detection.

Safety — the exact bytes this plugin puts on the wire
-----------------------------------------------------
S7comm speaks to PLCs that run physical processes, so this plugin sends the
smallest identification exchange the protocol defines and nothing else. Three
frames per port, in order, then the socket is closed:

1. COTP connection request (ISO 8073 CR TPDU inside an RFC 1006 TPKT). Without
   it the PLC will not accept any S7 payload at all::

       03 00 00 16 11 e0 00 00 00 01 00 c1 02 01 00 c2 02 01 02 c0 01 0a

   TPKT version 3, length 22; COTP CR (0xe0) with source TSAP 0x0100 and
   destination TSAP 0x0102 (rack 0 / slot 2, the default CPU slot) and a
   1024-byte TPDU size. This only opens a transport connection.

2. S7comm "Setup communication" (ROSCTR 0x01 Job, function 0xf0). This is the
   mandatory handshake that negotiates PDU size; it reads and writes nothing::

       03 00 00 19 02 f0 80 32 01 00 00 00 01 00 08 00 00 f0 00 00 01 00 01 01 e0

3. S7comm "Read SZL" (ROSCTR 0x07 Userdata, function group 0x11 CPU functions,
   subfunction 0x44) for SZL-ID 0x0011 index 0x0000 — *module identification*.
   SZL lists are the CPU's own read-only diagnostic buffer; 0x0011 returns the
   order number, basic hardware and firmware version records::

       03 00 00 21 02 f0 80 32 07 00 00 00 01 00 08 00 08
       00 01 12 04 11 44 01 00 ff 09 00 04 00 11 00 00

Deliberately never sent: any ROSCTR 0x01 read/write-variable job (function 0x04
/ 0x05), any PLC control job (0x28 P_PROGRAM stop/start, 0x29 PLC control), any
block up/download, and any password/protection-level function. There is no
retry loop and no slot sweep — one connection, three frames, close.
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

# See the module docstring for a field-by-field justification of each frame.
COTP_CONNECTION_REQUEST = bytes.fromhex(
    "03 00 00 16"           # TPKT: version 3, length 22
    "11 e0 00 00 00 01 00"  # COTP CR: LI 17, dst-ref 0, src-ref 1, class 0
    "c1 02 01 00"           # src TSAP 0x0100
    "c2 02 01 02"           # dst TSAP 0x0102 -> rack 0, slot 2 (default CPU slot)
    "c0 01 0a"              # TPDU size 2^10
)
S7_SETUP_COMMUNICATION = bytes.fromhex(
    "03 00 00 19"                          # TPKT: length 25
    "02 f0 80"                             # COTP DT, end of transmission
    "32 01 00 00 00 01 00 08 00 00"        # S7: Job, pdu-ref 1, param len 8, data len 0
    "f0 00 00 01 00 01 01 e0"              # Setup communication, PDU length 480
)
S7_READ_SZL_MODULE_ID = bytes.fromhex(
    "03 00 00 21"                          # TPKT: length 33
    "02 f0 80"                             # COTP DT, end of transmission
    "32 07 00 00 00 01 00 08 00 08"        # S7: Userdata, param len 8, data len 8
    "00 01 12 04 11 44 01 00"              # CPU functions / Read SZL request, sequence 1
    "ff 09 00 04 00 11 00 00"              # SZL-ID 0x0011, index 0x0000
)

_TPKT_VERSION = 0x03
_COTP_CONNECT_CONFIRM = 0xD0
_COTP_DATA = 0xF0
_S7_PROTOCOL_ID = 0x32
_S7_ROSCTR_ACK_DATA = 0x03
_S7_ROSCTR_USERDATA = 0x07
_SZL_READ_SUBFUNCTION = 0x44

_TIMEOUT = 5.0
_MAX_TPKT = 2048  # a module-identification reply is ~130 bytes; anything larger is not ours


class S7CommDetectPlugin(PluginBase):
    id = "services.s7comm_detect"
    name = "Siemens S7comm PLC Detection"
    description = "Detect exposed Siemens S7comm PLCs (detection only — single read-only SZL identification request)"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [102]
    # Read SZL reads the CPU's diagnostic buffer. No variable write, no PLC
    # control function and no block transfer is ever sent.
    destructive = False

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number != 102 or port.state != "open":
                continue
            if getattr(port, "protocol", "tcp") == "udp":
                continue  # ISO-TSAP is TCP only
            try:
                response = await self._probe_s7(host.ip, port.number)
            except Exception:
                # A PLC that drops the connection mid-handshake must never fail
                # the scan — it just means we cannot identify it.
                logger.debug("S7comm probe failed for %s:%s", host.ip, port.number, exc_info=True)
                continue
            identity = self._parse_szl_response(response) if response else None
            if identity:
                findings.append(self._make_finding(port.number, identity))
        return findings

    async def _probe_s7(self, ip: str, port: int) -> bytes | None:
        """Run the COTP + setup + Read SZL exchange once. Returns the raw SZL reply."""
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=_TIMEOUT)
        try:
            writer.write(COTP_CONNECTION_REQUEST)
            await writer.drain()
            cotp = await self._read_tpkt(reader)
            # 0xd0 = Connect Confirm. Anything else (0x80 Disconnect Request from a
            # PLC that rejects the TSAP, or a non-ISO service) means we stop here.
            if not cotp or len(cotp) < 6 or cotp[5] != _COTP_CONNECT_CONFIRM:
                return None

            writer.write(S7_SETUP_COMMUNICATION)
            await writer.drain()
            setup = await self._read_tpkt(reader)
            if not setup or len(setup) < 9 or setup[7] != _S7_PROTOCOL_ID or setup[8] != _S7_ROSCTR_ACK_DATA:
                return None

            writer.write(S7_READ_SZL_MODULE_ID)
            await writer.drain()
            return await self._read_tpkt(reader)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_tpkt(self, reader) -> bytes | None:
        """Read exactly one TPKT frame, using its own length field."""
        try:
            header = await asyncio.wait_for(reader.readexactly(4), timeout=_TIMEOUT)
        except Exception:
            return None
        if len(header) < 4 or header[0] != _TPKT_VERSION:
            return None
        length = struct.unpack_from(">H", header, 2)[0]
        if length < 4 or length > _MAX_TPKT:
            return None
        try:
            body = await asyncio.wait_for(reader.readexactly(length - 4), timeout=_TIMEOUT)
        except Exception:
            return None
        return header + body

    # ── parsing ───────────────────────────────────────────────────────────────

    def _parse_szl_response(self, data: bytes | None) -> dict | None:
        """Pull module / hardware / firmware out of an SZL 0x0011 reply.

        Returns None for anything that is not a successful S7comm SZL reply, so a
        truncated frame or a different protocol answering on 102 reports nothing.
        """
        if not data or len(data) < 29:  # TPKT 4 + COTP 3 + S7 header 10 + param 12
            return None
        if data[0] != _TPKT_VERSION or data[5] != _COTP_DATA:
            return None
        if data[7] != _S7_PROTOCOL_ID or data[8] != _S7_ROSCTR_USERDATA:
            return None

        param_len, data_len = struct.unpack_from(">HH", data, 13)
        param = data[17:17 + param_len]
        # Response parameter: 00 01 12 | len | type+group | subfunc | seq | ...
        if len(param) < 12 or param[5] != _SZL_READ_SUBFUNCTION:
            return None
        if struct.unpack_from(">H", param, 10)[0] != 0x0000:
            return None  # CPU answered with an SZL error code

        block = data[17 + param_len:17 + param_len + data_len]
        if len(block) < 12 or block[0] != 0xFF:
            return None  # data-block return code != success
        payload_len = struct.unpack_from(">H", block, 2)[0]
        payload = block[4:4 + payload_len]
        if len(payload) < 8:
            return None

        szl_id, _index, record_len, record_count = struct.unpack_from(">HHHH", payload, 0)
        if szl_id != 0x0011 or record_len < 28:
            return None

        identity: dict = {"module": None, "basic_hardware": None, "firmware": None}
        records = payload[8:]
        for i in range(min(record_count, len(records) // record_len)):
            record = records[i * record_len:(i + 1) * record_len]
            record_index = struct.unpack_from(">H", record, 0)[0]
            # MlfB (order number) is 20 bytes of padded ASCII.
            mlfb = record[2:22].decode("ascii", errors="ignore").replace("\x00", "").strip()
            if record_index == 0x0001:
                identity["module"] = mlfb or None
            elif record_index == 0x0006:
                identity["basic_hardware"] = mlfb or None
            elif record_index == 0x0007:
                # Ausbg1 high/low byte plus Ausbg2 low byte carry the firmware triple.
                identity["firmware"] = f"V{record[24]}.{record[25]}.{record[27]}"

        if not any(identity.values()):
            return None
        return identity

    def _make_finding(self, port: int, identity: dict) -> FindingData:
        module = identity.get("module") or "unknown"
        hardware = identity.get("basic_hardware") or "unknown"
        firmware = identity.get("firmware") or "unknown"
        evidence_lines = [
            "COTP connection accepted on TSAP 0x0102 (rack 0 / slot 2) and S7comm setup completed without credentials.",
            f"Read SZL 0x0011 (module identification) returned: module {module}, "
            f"basic hardware {hardware}, firmware {firmware}.",
        ]
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="Siemens S7comm PLC Exposed",
            description=(
                "A Siemens PLC answered an S7comm identification request with no credentials. "
                "S7comm has no authentication of its own on S7-300/S7-400 class CPUs, so anyone "
                "who can reach TCP 102 can read process variables and memory blocks and, using the "
                "same session, issue CPU control functions (STOP/START) or upload and download "
                "program blocks. Exposure of this port is therefore equivalent to physical access "
                "to the controller."
            ),
            evidence="\n".join(evidence_lines),
            remediation=(
                "S7comm cannot be authenticated, so protection has to be at the network layer. "
                "Remove TCP 102 from any routable or internet-facing path and place the PLC in a "
                "dedicated cell behind an industrial firewall that permits ISO-TSAP only from the "
                "engineering workstations that need it. Reach it remotely through a VPN or jump "
                "host, never directly. Where the CPU supports it, set a protection level with a "
                "password and enable the S7-1200/1500 secure communication features."
            ),
            references=[
                "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-205a",
                "https://cert-portal.siemens.com/productcert/",
            ],
            port_number=port,
            protocol="tcp",
        )
