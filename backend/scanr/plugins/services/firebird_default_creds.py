"""Firebird database default credentials check.

Firebird databases commonly ship with a default SYSDBA account and password
of 'masterkey'. Access with these credentials provides full database control.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_DEFAULT_CREDS = [
    ("sysdba", "masterkey"),
    ("sysdba", "masterke"),   # truncated (older Firebird)
    ("SYSDBA", "masterkey"),
]


class FirebirdDefaultCredsPlugin(PluginBase):
    id = "services.firebird_default_creds"
    name = "Firebird Default Credentials"
    description = "Test Firebird database for default SYSDBA/masterkey credentials"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [3050]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        for port in host.ports:
            if port.number != 3050 or port.state != "open":
                continue
            found = await asyncio.get_event_loop().run_in_executor(
                None, self._try_default_creds, host.ip, 3050
            )
            if found:
                username, password = found
                return [FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="Firebird Database Accepts Default Credentials",
                    description=(
                        "The Firebird database server accepts the default SYSDBA credentials. "
                        "An attacker with network access can log in with full database "
                        "administrator privileges, read or modify all data, and potentially "
                        "execute operating system commands via stored procedures."
                    ),
                    evidence=f"Authentication succeeded on {host.ip}:3050 with {username}:{password}",
                    remediation=(
                        "Immediately change the SYSDBA password using gsec: "
                        "'gsec -user sysdba -password masterkey -mo sysdba -pw <newpassword>'. "
                        "Restrict Firebird network access via firewall to trusted hosts only."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1078.001/",
                        "https://firebirdsql.org/en/firebird-technical-documentation/",
                    ],
                    port_number=3050,
                    protocol="tcp",
                )]
        return []

    def _try_default_creds(self, ip: str, port: int) -> tuple[str, str] | None:
        try:
            import fdb
        except ImportError:
            return self._try_via_socket(ip, port)

        for username, password in _DEFAULT_CREDS:
            try:
                conn = fdb.connect(
                    host=ip,
                    port=port,
                    database="employee",  # default sample db
                    user=username,
                    password=password,
                    timeout=8,
                )
                conn.close()
                return (username, password)
            except Exception:
                pass
        return None

    def _try_via_socket(self, ip: str, port: int) -> tuple[str, str] | None:
        """Firebird wire protocol probe when fdb driver is unavailable."""
        import socket
        import struct

        # Firebird op_connect (1) packet
        user = b"sysdba"
        password = b"masterkey"
        database = b"/tmp/test.gdb\x00"

        dpb = (
            b"\x01"           # dpb version
            b"\x1c" + bytes([len(user)]) + user +        # isc_dpb_user_name
            b"\x1d" + bytes([len(password)]) + password   # isc_dpb_password
        )

        op_connect = struct.pack(">I", 1) + database + struct.pack(">II", 2, len(dpb)) + dpb

        try:
            sock = socket.create_connection((ip, port), timeout=8)
            sock.sendall(op_connect)
            resp = sock.recv(16)
            sock.close()
            # op_accept = 3, op_reject = 4
            if len(resp) >= 4:
                op = struct.unpack(">I", resp[:4])[0]
                if op == 3:
                    return ("sysdba", "masterkey")
        except Exception:
            pass
        return None
