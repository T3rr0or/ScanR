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
    ("postgres", "postgres", "postgres"),
    ("postgres", "", "postgres"),
    ("postgres", "postgres", "template1"),
    ("postgres", "", "template1"),
    ("admin", "admin", "postgres"),
    ("postgres", "password", "postgres"),
]


class PostgresUnauthPlugin(PluginBase):
    id = "services.postgres_unauth"
    name = "PostgreSQL Default Credentials"
    description = "Detect PostgreSQL with default or trust-authenticated access"
    category = PluginCategory.services
    severity = Severity.high
    ports = [5432]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 5432 and p.state == "open" for p in host.ports):
            return []
        result = await self._test_postgres(host.ip)
        return [result] if result else []

    async def _test_postgres(self, ip: str) -> FindingData | None:
        import asyncpg

        for user, password, database in _DEFAULT_CREDS:
            try:
                conn = await asyncio.wait_for(
                    asyncpg.connect(
                        host=ip,
                        port=5432,
                        user=user,
                        password=password,
                        database=database,
                        timeout=5,
                    ),
                    timeout=6.0,
                )
                version = await conn.fetchval("SELECT version()")
                await conn.close()

                return FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="PostgreSQL Default Credentials",
                    description=(
                        f"The PostgreSQL server at {ip}:5432 accepts default credentials. "
                        f"Server: {str(version)[:100]}. "
                        "An attacker can access all databases the user has privileges on."
                    ),
                    evidence=f"Login succeeded: user={user!r}, password={'(blank)' if not password else repr(password)}, db={database!r}",
                    remediation=(
                        "Change the postgres superuser password: ALTER USER postgres PASSWORD 'StrongPassword'. "
                        "Change pg_hba.conf to use 'scram-sha-256' instead of 'trust'. "
                        "Bind PostgreSQL to localhost (listen_addresses = 'localhost'). "
                        "Block port 5432 at the firewall."
                    ),
                    references=[
                        "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
                        "https://www.postgresql.org/docs/current/auth-methods.html",
                    ],
                    port_number=5432,
                    protocol="tcp",
                )
            except asyncio.TimeoutError:
                pass
            except Exception as exc:
                logger.debug(
                    "PostgreSQL test failed (%s:%s@%s): %s", user, password, database, exc
                )

        return None
