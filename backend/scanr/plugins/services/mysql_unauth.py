from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_DEFAULT_CREDS = [
    ("root", ""),
    ("root", "root"),
    ("root", "mysql"),
    ("", ""),
]


class MysqlUnauthPlugin(PluginBase):
    id = "services.mysql_unauth"
    name = "MySQL Anonymous/Default Root Access"
    description = "Detect MySQL with anonymous or default root access"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [3306]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 3306 and p.state == "open" for p in host.ports):
            return []
        result = await asyncio.get_event_loop().run_in_executor(
            None, self._test_mysql, host.ip
        )
        return [result] if result else []

    def _test_mysql(self, ip: str) -> FindingData | None:
        for username, password in _DEFAULT_CREDS:
            try:
                sock = socket.create_connection((ip, 3306), timeout=5)
                # Read server greeting
                data = sock.recv(4096)
                if not data or len(data) < 5:
                    sock.close()
                    continue

                # Parse MySQL packet header: 3 bytes length + 1 byte seq
                pkt_len = struct.unpack_from("<I", data[:4])[0] & 0xFFFFFF
                payload = data[4 : 4 + pkt_len]

                if not payload or payload[0] == 0xFF:  # Error packet
                    sock.close()
                    continue

                # Protocol version byte
                proto_ver = payload[0]
                if proto_ver not in (9, 10):  # MySQL protocol versions
                    sock.close()
                    continue

                # Extract server version string (null-terminated after proto_ver)
                null_idx = payload.find(b"\x00", 1)
                server_version = (
                    payload[1:null_idx].decode(errors="ignore")
                    if null_idx > 0
                    else "unknown"
                )

                if null_idx < 0 or len(payload) < null_idx + 9:
                    sock.close()
                    continue

                # Build auth response packet
                # Client capabilities: LONG_PASSWORD | CONNECT_WITH_DB | SECURE_CONNECTION
                client_caps = 0x0001 | 0x0200 | 0x8000

                user_bytes = username.encode() + b"\x00"
                payload_out = (
                    struct.pack("<I", client_caps | (1 << 24))[:3]  # capabilities
                    + b"\x01\x00\x00\x00"  # max packet
                    + b"\x21"  # charset utf8
                    + b"\x00" * 23  # reserved
                    + user_bytes
                    + b"\x00"  # auth response length 0 = empty password
                )

                pkt = struct.pack("<I", len(payload_out))[:3] + b"\x01" + payload_out
                sock.sendall(pkt)

                resp = sock.recv(4096)
                sock.close()

                if resp and len(resp) >= 5:
                    resp_payload = resp[4:]
                    if resp_payload[0] == 0x00:  # OK packet
                        return FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title="MySQL Anonymous/Default Root Access",
                            description=(
                                f"The MySQL server at {ip}:3306 accepts connections with username={username!r} "
                                f"and empty password. Server version: {server_version}. "
                                "An attacker can read all databases including user credential hashes."
                            ),
                            evidence=f"username={username!r}, password='(empty)', server={server_version}",
                            remediation=(
                                "Set a strong root password immediately: ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPassword'. "
                                "Remove anonymous accounts: DELETE FROM mysql.user WHERE User=''. "
                                "Bind MySQL to localhost (bind-address = 127.0.0.1). "
                                "Block port 3306 at the firewall."
                            ),
                            references=[
                                "https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html",
                            ],
                            port_number=3306,
                            protocol="tcp",
                        )
            except Exception as exc:
                logger.debug(
                    "MySQL test failed (%s:%s): %s", username, password, exc
                )

        return None
