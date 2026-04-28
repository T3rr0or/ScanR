"""SMB NULL session authentication check.

A NULL session uses a blank username and password to authenticate to SMB.
This can expose share lists, user accounts, and password policies to
unauthenticated attackers.
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


class SmbNullSessionPlugin(PluginBase):
    id = "services.smb_null_session"
    name = "SMB NULL Session Authentication"
    description = "Check if SMB server accepts NULL session (blank username/password)"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [445, 139]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        for port in host.ports:
            if port.number not in (445, 139) or port.state != "open":
                continue
            result = await asyncio.get_running_loop().run_in_executor(
                None, self._check_null_session, host.ip
            )
            if result is not None:
                shares_line = f"\nAccessible shares: {', '.join(result)}" if result else ""
                return [FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="SMB NULL Session Authentication Accepted",
                    description=(
                        "The SMB server accepts authentication with a blank username and "
                        "password (NULL session). This allows unauthenticated users to "
                        "enumerate shares, user accounts, and potentially retrieve sensitive "
                        "data or upload malicious files to writable shares."
                    ),
                    evidence=f"NULL session authentication succeeded on {host.ip}:445{shares_line}",
                    remediation=(
                        "Disable SMB NULL session access via Group Policy: "
                        "Network access: Restrict anonymous access to Named Pipes and Shares = Enabled. "
                        "Also set 'RestrictNullSessAccess = 1' under "
                        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters."
                    ),
                    references=[
                        "https://www.beyondsecurity.com/resources/vulnerabilities/null-session-availablesmb",
                        "https://techcommunity.microsoft.com/blog/filecab/smb-and-null-sessions-why-your-pen-test-is-probably-wrong/1185365",
                    ],
                    port_number=445,
                    protocol="tcp",
                )]
        return []

    def _check_null_session(self, ip: str) -> list[str] | None:
        """Return list of share names on success, empty list if auth succeeded but no shares, None on failure."""
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            logger.debug("impacket not available — skipping SMB NULL session check")
            return None

        try:
            conn = SMBConnection(ip, ip, timeout=8)
            conn.login("", "")
            shares: list[str] = []
            try:
                for share in conn.listShares():
                    name = share["shi1_netname"].decode("utf-16-le").rstrip("\x00")
                    shares.append(name)
            except Exception:
                pass
            conn.logoff()
            return shares
        except Exception:
            return None
