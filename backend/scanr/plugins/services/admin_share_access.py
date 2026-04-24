"""Administrative SMB share access check.

Tests whether domain credentials grant local administrator access on a target
host by attempting to connect to ADMIN$ and C$ shares via SMB. Successful
access indicates the account can execute code and perform lateral movement.
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


class AdminShareAccessPlugin(PluginBase):
    id = "services.admin_share_access"
    name = "Admin Share Access Check"
    description = "Test if domain credentials grant local admin access via ADMIN$/C$ shares"
    category = PluginCategory.services
    severity = Severity.high
    ports = [445]
    requires_auth = True

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        open_ports = {p.number for p in host.ports if p.state == "open"}
        if 445 not in open_ports:
            return []

        creds = context.credential_data or {}
        username = creds.get("username", "")
        password = creds.get("password", "")
        domain = creds.get("domain", "")
        if not username or not domain:
            return []

        result = await asyncio.get_event_loop().run_in_executor(
            None, self._check_admin_shares, host.ip, username, password, domain
        )
        return [result] if result is not None else []

    def _check_admin_shares(self, ip: str, username: str, password: str, domain: str) -> FindingData | None:
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            logger.debug("impacket not available — skipping admin_share_access")
            return None

        accessible_shares = []

        try:
            smb = SMBConnection(ip, ip, timeout=10)
            smb.login(username, password, domain=domain)

            # Try ADMIN$ (most definitive admin check)
            try:
                smb.connectTree("ADMIN$")
                accessible_shares.append("ADMIN$")
            except Exception:
                pass

            # Try C$ (also requires local admin)
            try:
                smb.connectTree("C$")
                accessible_shares.append("C$")
                # List root to confirm access
                try:
                    files = smb.listPath("C$", "\\*")
                    if files:
                        accessible_shares[-1] = f"C$ (listed {len(files)} items in root)"
                except Exception:
                    pass
            except Exception:
                pass

            smb.logoff()

            if not accessible_shares:
                return None

            return FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title=f"Local Admin Access via SMB — {ip}",
                description=(
                    f"The domain account {domain}\\{username} has local administrator access on {ip} "
                    f"via administrative SMB shares. This indicates the account can execute code, "
                    "read all files, and perform lateral movement to this host."
                ),
                evidence=f"Accessible admin shares on {ip}: {', '.join(accessible_shares)}",
                remediation=(
                    "Review local administrator group membership on all hosts. "
                    "Implement the Principle of Least Privilege — domain users should not be local admins unless required. "
                    "Use Local Administrator Password Solution (LAPS) to randomise local admin passwords. "
                    "Disable administrative shares if not required (AutoShareWks=0 in registry)."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-automatic-creation-of-shared-folders",
                    "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
                ],
                port_number=445,
                protocol="tcp",
            )
        except Exception as exc:
            logger.debug("Admin share check failed on %s: %s", ip, exc)
            return None
