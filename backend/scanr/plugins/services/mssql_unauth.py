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
    ("sa", ""),
    ("sa", "sa"),
    ("sa", "password"),
    ("sa", "Password1"),
    ("sa", "admin"),
    ("sa", "1234"),
]


class MssqlUnauthPlugin(PluginBase):
    id = "services.mssql_unauth"
    name = "MSSQL Default/Blank SA Credentials"
    description = "Test MSSQL for default and blank SA credentials"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [1433]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 1433 and p.state == "open" for p in host.ports):
            return []
        result = await asyncio.get_event_loop().run_in_executor(
            None, self._test_mssql, host.ip
        )
        return [result] if result else []

    def _test_mssql(self, ip: str) -> FindingData | None:
        try:
            from impacket.tds import MSSQL, DummyPrint
        except ImportError:
            logger.debug("impacket not available — skipping mssql_unauth")
            return None

        for username, password in _DEFAULT_CREDS:
            try:
                ms = MSSQL(ip, 1433, DummyPrint())
                ms.connect()
                auth_ok = ms.login(None, username, password, None, None, False)
                if auth_ok:
                    ms.disconnect()
                    return FindingData(
                        plugin_id=self.id,
                        severity=Severity.critical,
                        title="MSSQL Default Credentials — SA Account Accessible",
                        description=(
                            f"The MSSQL server at {ip}:1433 accepts default credentials for the SA (sysadmin) account. "
                            "Full sysadmin access allows reading all databases, executing OS commands via xp_cmdshell, "
                            "and potentially achieving SYSTEM-level command execution on the host."
                        ),
                        evidence=f"Login succeeded: username={username!r}, password={'(blank)' if not password else '(set)'}",
                        remediation=(
                            "Change the SA account password immediately to a strong, unique value. "
                            "Disable the SA account if not required. "
                            "Enable Windows Authentication mode only. "
                            "Block port 1433 from internet-facing interfaces."
                        ),
                        references=[
                            "https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode",
                        ],
                        port_number=1433,
                        protocol="tcp",
                    )
                ms.disconnect()
            except Exception as exc:
                logger.debug(
                    "MSSQL login attempt failed (%s/%s): %s", username, password, exc
                )

        # Also check SQL Browser UDP 1434
        self._check_sql_browser(ip)
        return None

    def _check_sql_browser(self, ip: str) -> None:
        """Enumerate MSSQL instances via SQL Server Browser (UDP 1434)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(b"\x02", (ip, 1434))
            data, _ = sock.recvfrom(4096)
            sock.close()
            if data:
                logger.info(
                    "SQL Browser response from %s: %s",
                    ip,
                    data[3:].decode(errors="ignore")[:200],
                )
        except Exception:
            pass
