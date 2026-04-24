"""gMSA readable password check.

Group Managed Service Accounts (gMSA) store their current password in the
msDS-ManagedPassword LDAP attribute. If the authenticated user can read this
attribute, they can compute and use the gMSA password to authenticate as the
service account.
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


class GmsaReadablePlugin(PluginBase):
    id = "services.gmsa_readable"
    name = "gMSA Readable Password Check"
    description = "Check if gMSA (Group Managed Service Account) passwords are readable by current user"
    category = PluginCategory.services
    severity = Severity.high
    ports = [389]
    requires_auth = True

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        open_ports = {p.number for p in host.ports if p.state == "open"}
        if 389 not in open_ports:
            return []

        creds = context.credential_data or {}
        username = creds.get("username", "")
        password = creds.get("password", "")
        domain = creds.get("domain", "")
        if not username or not domain:
            return []

        return await asyncio.get_event_loop().run_in_executor(
            None, self._check_gmsa, host.ip, username, password, domain
        )

    def _check_gmsa(self, ip: str, username: str, password: str, domain: str) -> list[FindingData]:
        try:
            import ldap3
        except ImportError:
            return []

        base_dn = ",".join(f"DC={p}" for p in domain.split(".") if p)
        bind_user = f"{domain}\\{username}" if "\\" not in username else username

        try:
            server = ldap3.Server(ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
            conn = ldap3.Connection(server, user=bind_user, password=password, auto_bind=True, receive_timeout=15)

            # Find gMSA accounts
            conn.search(
                base_dn,
                "(objectClass=msDS-GroupManagedServiceAccount)",
                attributes=["sAMAccountName", "msDS-ManagedPassword", "msDS-ManagedPasswordInterval",
                            "msDS-GroupMSAMembership", "distinguishedName"],
                search_scope=ldap3.SUBTREE,
            )

            readable_gmsas = []
            for entry in conn.entries:
                name = str(entry.sAMAccountName)
                # If msDS-ManagedPassword is readable (not empty/error), the current user can read it
                pwd_data = entry["msDS-ManagedPassword"].raw_values if entry["msDS-ManagedPassword"] else None
                if pwd_data:
                    readable_gmsas.append(name)

            conn.unbind()

            if not readable_gmsas:
                return []

            return [FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title=f"gMSA Password Readable — {len(readable_gmsas)} Account(s)",
                description=(
                    f"The msDS-ManagedPassword attribute is readable for {len(readable_gmsas)} gMSA account(s) "
                    f"with the current credentials ({username}). "
                    "An attacker who has compromised this account can extract the gMSA password and "
                    "authenticate as the service account, potentially gaining elevated privileges."
                ),
                evidence="Readable gMSA accounts:\n" + "\n".join(f"  {a}" for a in readable_gmsas),
                remediation=(
                    "Audit the msDS-GroupMSAMembership attribute for each gMSA. "
                    "Remove non-essential principals from the GMSA membership list. "
                    "Ensure gMSA accounts don't have unnecessary high-privilege group memberships."
                ),
                references=[
                    "https://www.thehacker.recipes/ad/movement/credentials/dumping/gmsa",
                    "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview",
                ],
                port_number=389,
                protocol="tcp",
            )]
        except Exception as exc:
            logger.debug("gMSA check failed on %s: %s", ip, exc)
            return []
