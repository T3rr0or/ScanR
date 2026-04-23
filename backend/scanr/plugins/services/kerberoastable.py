"""Kerberoasting — enumerate accounts with SPNs susceptible to offline cracking.

Requests TGS tickets for accounts with Service Principal Names set.
These tickets can be cracked offline to recover service account passwords.
"""
from __future__ import annotations
import asyncio, logging
from typing import TYPE_CHECKING
from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class KerberoastablePlugin(PluginBase):
    id = "services.kerberoastable"
    name = "Kerberoastable Service Accounts"
    description = "Find accounts with SPNs that can be Kerberoasted for offline password cracking"
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

        username = creds["username"]
        password = creds.get("password", "")
        domain = creds.get("domain", "")
        if not domain:
            return []

        results = await asyncio.get_event_loop().run_in_executor(
            None, self._find_spns, host.ip, username, password, domain
        )
        return results

    def _find_spns(self, dc_ip: str, username: str, password: str, domain: str) -> list[FindingData]:
        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5 import constants
            from impacket.krb5.types import Principal
            import ldap3
        except ImportError:
            logger.warning("impacket/ldap3 not available — skipping kerberoasting check")
            return []

        try:
            server = ldap3.Server(dc_ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
            bind_user = f"{domain}\\{username}" if "\\" not in username else username
            conn = ldap3.Connection(server, user=bind_user, password=password, auto_bind=True, receive_timeout=15)

            base_dn = ",".join(f"DC={p}" for p in domain.replace("\\", "").split(".") if p)
            conn.search(
                base_dn,
                "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName", "servicePrincipalName", "distinguishedName"],
            )
            spn_accounts = list(conn.entries)
            conn.unbind()

            if not spn_accounts:
                return []

            account_lines = []
            for entry in spn_accounts[:50]:
                sam = str(entry.sAMAccountName)
                spns = entry.servicePrincipalName.values if hasattr(entry, "servicePrincipalName") else []
                account_lines.append(f"  {sam}: {', '.join(str(s) for s in spns)}")

            return [FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title=f"Kerberoastable Accounts Found — {len(spn_accounts)} SPN(s)",
                description=(
                    f"{len(spn_accounts)} user account(s) with Service Principal Names (SPNs) were found. "
                    "These accounts can be Kerberoasted: an authenticated user can request TGS tickets and "
                    "crack them offline to recover the service account passwords."
                ),
                evidence="Accounts with SPNs:\n" + "\n".join(account_lines),
                port_number=88,
                protocol="tcp",
                remediation=(
                    "Use Group Managed Service Accounts (gMSA) to eliminate static passwords. "
                    "Ensure service account passwords are >25 chars, randomly generated, and rotated regularly. "
                    "Remove SPNs from accounts that no longer need them."
                ),
            )]
        except Exception as exc:
            logger.debug("Kerberoastable check failed on %s: %s", dc_ip, exc)
            return []
