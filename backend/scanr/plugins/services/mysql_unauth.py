from __future__ import annotations

import logging
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
    description = "Detect MySQL with anonymous or default root access (supports MySQL 5.x and 8.x)"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [3306]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 3306 and p.state == "open" for p in host.ports):
            return []
        result = await self._test_mysql(host.ip)
        return [result] if result else []

    async def _test_mysql(self, ip: str) -> FindingData | None:
        try:
            import aiomysql
        except ImportError:
            logger.debug("aiomysql not installed — mysql_unauth plugin skipped")
            return None

        for username, password in _DEFAULT_CREDS:
            try:
                conn = await aiomysql.connect(
                    host=ip,
                    port=3306,
                    user=username,
                    password=password,
                    connect_timeout=5,
                    auth_plugin="mysql_native_password",
                )
                server_version = conn.get_server_info()
                await conn.ensure_closed()
                return FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="MySQL Anonymous/Default Root Access",
                    description=(
                        f"The MySQL server at {ip}:3306 accepts connections with "
                        f"username={username!r} and password={'(empty)' if not password else repr(password)}. "
                        f"Server version: {server_version}. "
                        "An attacker can read all databases including user credential hashes."
                    ),
                    evidence=f"username={username!r}, password={'(empty)' if not password else repr(password)}, server={server_version}",
                    remediation=(
                        "Set a strong root password: ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPassword'. "
                        "Remove anonymous accounts: DELETE FROM mysql.user WHERE User=''. "
                        "Bind MySQL to localhost (bind-address = 127.0.0.1). "
                        "Block port 3306 at the firewall."
                    ),
                    references=["https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html"],
                    port_number=3306,
                    protocol="tcp",
                )
            except Exception as exc:
                logger.debug("MySQL test failed (%s:%s@%s): %s", username, password, ip, exc)

        return None
