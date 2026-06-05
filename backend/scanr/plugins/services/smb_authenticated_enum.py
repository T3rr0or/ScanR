"""Authenticated SMB enumeration — sessions, logged-on users, local groups.

Uses domain credentials to enumerate active SMB sessions and local
administrator group membership on each host.
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


class SmbAuthenticatedEnumPlugin(PluginBase):
    id = "services.smb_authenticated_enum"
    name = "SMB Authenticated Session Enumeration"
    description = "Enumerate SMB sessions, logged-on users, and local admins using domain credentials"
    category = PluginCategory.services
    severity = Severity.medium
    requires_auth = True
    ports = [445]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 445 and p.state == "open" for p in host.ports):
            return []
        creds = context.credential("primary_domain") or context.credential("local_admin") or context.credential_data
        if not creds or not creds.get("username"):
            return []

        results = await asyncio.get_running_loop().run_in_executor(
            None, self._smb_enum, host.ip, creds.get("username", ""), creds.get("password", ""), creds.get("domain", "")
        )
        return results

    def _smb_enum(self, ip: str, username: str, password: str, domain: str) -> list[FindingData]:
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            logger.warning("impacket not available — skipping smb_authenticated_enum")
            return []

        findings = []
        try:
            smb = SMBConnection(ip, ip, timeout=15)
            smb.login(username, password, domain=domain)

            try:
                smb.listOpenFiles()
            except Exception:
                pass

            users_loggedon = []
            try:
                resp = smb.getSessionEnum()
                users_loggedon = [str(s["wki1_username"]) for s in resp if s.get("wki1_username")] if resp else []
            except Exception:
                pass

            smb.logoff()

            if users_loggedon:
                findings.append(
                    FindingData(
                        plugin_id=self.id,
                        severity=Severity.info,
                        title=f"Active SMB Sessions — {len(users_loggedon)} User(s) Logged On",
                        description=(
                            f"Authenticated SMB enumeration found {len(users_loggedon)} active user session(s) on {ip}. "
                            "This reveals which users are currently active on the host."
                        ),
                        evidence="Logged-on users:\n" + "\n".join(f"  {u}" for u in users_loggedon[:20]),
                        port_number=445,
                        protocol="tcp",
                        remediation="Restrict NetSessionEnum to Domain Admins via Group Policy "
                        "(Network access: Restrict clients allowed to make remote calls to SAM).",
                    )
                )

        except Exception as exc:
            logger.debug("SMB authenticated enum failed on %s: %s", ip, exc)

        return findings
