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


def _build_ismaster_msg() -> bytes:
    """Build a minimal MongoDB OP_MSG isMaster/hello command."""
    # OP_MSG with {isMaster: 1} body
    doc_bytes = (
        b"\x15\x00\x00\x00"  # doc length = 21
        b"\x10"              # int32 type
        b"isMaster\x00"      # key
        b"\x01\x00\x00\x00"  # value: 1
        b"\x00"              # end of doc
    )
    # OP_MSG header: messageLength(4) + requestID(4) + responseTo(4) + opCode(4) + flagBits(4)
    flag_bits = b"\x00\x00\x00\x00"
    section_kind = b"\x00"  # body section
    payload = flag_bits + section_kind + doc_bytes
    header = struct.pack("<iiii", 16 + len(payload), 1, 0, 2013)  # opCode 2013 = OP_MSG
    return header + payload


class MongoDBUnauthPlugin(PluginBase):
    id = "services.mongodb_unauth"
    name = "MongoDB Unauthenticated Access"
    description = "Detect MongoDB instances accessible without authentication"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [27017, 27018, 27019]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in (27017, 27018, 27019) or port.state != "open":
                continue
            result = await self._probe(host.ip, port.number)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, ip: str, port: int) -> FindingData | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5.0
            )
            writer.write(_build_ismaster_msg())
            await writer.drain()
            # Read response header (16 bytes)
            header = await asyncio.wait_for(reader.read(16), timeout=3.0)
            if len(header) < 16:
                writer.close()
                return None
            msg_len = struct.unpack("<i", header[:4])[0]
            # Read rest of response
            body = await asyncio.wait_for(reader.read(msg_len - 16), timeout=3.0)
            writer.close()

            # A valid response means no auth required for connection
            if body and len(body) > 4:
                # Try to extract version from BSON (simple text search)
                text = body.decode(errors="ignore")
                version = "unknown"
                if "version" in text:
                    idx = text.find("version")
                    snippet = text[idx:idx+30]
                    import re
                    m = re.search(r"(\d+\.\d+\.\d+)", snippet)
                    if m:
                        version = m.group(1)

                return FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="MongoDB Unauthenticated Access",
                    description=(
                        f"The MongoDB instance on port {port} (v{version}) responds to connection "
                        "attempts without requiring authentication. "
                        "An attacker may be able to enumerate databases and read/write data."
                    ),
                    evidence=f"TCP connect + isMaster to {ip}:{port} → valid MongoDB response (v{version})",
                    remediation=(
                        "Enable MongoDB authentication (security.authorization: enabled in mongod.conf). "
                        "Bind MongoDB to localhost or use firewall rules to restrict access."
                    ),
                    references=[
                        "https://www.mongodb.com/docs/manual/tutorial/enable-authentication/",
                    ],
                    port_number=port,
                    protocol="tcp",
                )
        except Exception:
            pass
        return None
