"""Kerberos delegation check.

Finds computer accounts with unconstrained delegation (UAC flag 0x80000) and
user/computer accounts configured for constrained delegation via
msDS-AllowedToDelegateTo. Unconstrained delegation allows an attacker who
compromises the machine to capture TGTs for any user who authenticates to it.
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


class UnconstrainedDelegationPlugin(PluginBase):
    id = "services.unconstrained_delegation"
    name = "Kerberos Delegation Check"
    description = "Find computers with Kerberos unconstrained delegation (UAC flag 0x80000)"
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

        return await asyncio.get_running_loop().run_in_executor(
            None, self._find_delegation, host.ip, username, password, domain
        )

    def _find_delegation(self, ip: str, username: str, password: str, domain: str) -> list[FindingData]:
        try:
            import ldap3
        except ImportError:
            return []

        base_dn = ",".join(f"DC={p}" for p in domain.split(".") if p)
        bind_user = f"{domain}\\{username}" if "\\" not in username else username
        findings = []

        try:
            server = ldap3.Server(ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
            conn = ldap3.Connection(server, user=bind_user, password=password, auto_bind=True, receive_timeout=15)

            # Find unconstrained delegation (UAC & 0x80000 = 524288)
            # Exclude DCs (objectCategory=computer AND NOT in Domain Controllers OU)
            conn.search(
                base_dn,
                "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))",
                attributes=["sAMAccountName", "operatingSystem", "lastLogon", "distinguishedName"],
                search_scope=ldap3.SUBTREE,
            )

            unconstrained = list(conn.entries)
            if unconstrained:
                lines = []
                for entry in unconstrained[:30]:
                    name = str(entry.sAMAccountName)
                    os_name = str(entry.operatingSystem) if entry.operatingSystem else "unknown OS"
                    lines.append(f"  {name} ({os_name})")

                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title=f"Kerberos Unconstrained Delegation — {len(unconstrained)} Computer(s)",
                    description=(
                        f"{len(unconstrained)} non-DC computer account(s) are configured with unconstrained delegation. "
                        "If an attacker compromises one of these machines, they can capture Kerberos TGTs "
                        "from any user authenticating to it (including Domain Admins), enabling impersonation of any domain user."
                    ),
                    evidence="Computers with unconstrained delegation:\n" + "\n".join(lines),
                    remediation=(
                        "Replace unconstrained delegation with constrained delegation or resource-based constrained delegation (RBCD). "
                        "Set TRUSTED_FOR_DELEGATION to false in computer account properties. "
                        "Enable Protected Users security group for sensitive accounts to prevent delegation."
                    ),
                    references=[
                        "https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained",
                        "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview",
                    ],
                    port_number=389,
                    protocol="tcp",
                ))

            # Find constrained delegation (msDS-AllowedToDelegateTo set)
            conn.search(
                base_dn,
                "(&(|(objectClass=user)(objectClass=computer))(msDS-AllowedToDelegateTo=*))",
                attributes=["sAMAccountName", "msDS-AllowedToDelegateTo", "distinguishedName"],
                search_scope=ldap3.SUBTREE,
            )

            constrained = list(conn.entries)
            if constrained:
                lines = []
                for entry in constrained[:20]:
                    name = str(entry.sAMAccountName)
                    targets = list(entry["msDS-AllowedToDelegateTo"].values)[:5] if entry["msDS-AllowedToDelegateTo"] else []
                    lines.append(f"  {name} → {', '.join(str(t) for t in targets)}")

                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title=f"Kerberos Constrained Delegation — {len(constrained)} Account(s)",
                    description=(
                        f"{len(constrained)} account(s) are configured with constrained delegation. "
                        "Constrained delegation allows these accounts to impersonate users to specific services, "
                        "which can still be abused if the account itself is compromised."
                    ),
                    evidence="Accounts with constrained delegation:\n" + "\n".join(lines),
                    remediation=(
                        "Review whether each constrained delegation assignment is necessary. "
                        "Prefer resource-based constrained delegation (RBCD) as it is more auditable. "
                        "Apply Protected Users group to sensitive accounts."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview",
                    ],
                    port_number=389,
                    protocol="tcp",
                ))

            conn.unbind()
        except Exception as exc:
            logger.debug("Delegation check failed on %s: %s", ip, exc)

        return findings
