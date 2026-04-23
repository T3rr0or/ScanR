"""AS-REP Roasting — find accounts with Kerberos pre-authentication disabled.

These accounts' AS-REP responses can be captured and cracked offline
without any credentials.
"""
from __future__ import annotations
import asyncio, logging
from typing import TYPE_CHECKING
from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class AsreproastablePlugin(PluginBase):
    id = "services.asreproastable"
    name = "AS-REP Roastable Accounts"
    description = "Find accounts with Kerberos pre-authentication disabled — crackable without credentials"
    category = PluginCategory.services
    severity = Severity.high
    requires_auth = True
    ports = [88]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 88 and p.state == "open" for p in host.ports):
            return []
        creds = context.credential("primary_domain") or context.credential_data
        if not creds or not creds.get("username"):
            return []

        domain = creds.get("domain", "")
        if not domain:
            return []

        results = await asyncio.get_event_loop().run_in_executor(
            None, self._find_asrep, host.ip, creds.get("username", ""), creds.get("password", ""), domain
        )
        return results

    def _find_asrep(self, dc_ip: str, username: str, password: str, domain: str) -> list[FindingData]:
        try:
            import ldap3
        except ImportError:
            logger.warning("ldap3 not available — skipping asreproast check")
            return []

        try:
            server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
            bind_user = f"{domain}\\{username}" if "\\" not in username else username
            conn = ldap3.Connection(server, user=bind_user, password=password, auto_bind=True, receive_timeout=15)

            base_dn = ",".join(f"DC={p}" for p in domain.replace("\\", "").split(".") if p)
            # UAC flag 0x400000 = DONT_REQUIRE_PREAUTH
            conn.search(
                base_dn,
                "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                attributes=["sAMAccountName"],
            )
            vuln_accounts = [str(e.sAMAccountName) for e in conn.entries]
            conn.unbind()

            if not vuln_accounts:
                return []

            return [FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title=f"AS-REP Roastable Accounts — {len(vuln_accounts)} Account(s)",
                description=(
                    f"{len(vuln_accounts)} account(s) have Kerberos pre-authentication disabled. "
                    "An attacker can request AS-REP responses for these accounts without any credentials "
                    "and crack them offline to obtain the account passwords."
                ),
                evidence="Accounts without pre-auth:\n" + "\n".join(f"  {a}" for a in vuln_accounts[:50]),
                port_number=88,
                protocol="tcp",
                remediation="Enable Kerberos pre-authentication on all accounts (remove DONT_REQUIRE_PREAUTH flag). "
                            "Use strong, unique passwords for any accounts that require this setting.",
            )]
        except Exception as exc:
            logger.debug("AS-REP roast check failed on %s: %s", dc_ip, exc)
            return []
