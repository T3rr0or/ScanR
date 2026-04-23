"""SMB share enumeration with write-access detection.

Lists accessible SMB shares and flags any configured with write access,
which could allow an attacker to upload malicious files.
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


class SmbShareEnumPlugin(PluginBase):
    id = "services.smb_share_enum"
    name = "SMB Writable Share"
    description = "Enumerate SMB shares and detect write access using provided credentials"
    category = PluginCategory.services
    severity = Severity.high
    requires_auth = True
    ports = [445]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 445 and p.state == "open" for p in host.ports):
            return []

        creds = context.credential("primary_domain") or context.credential("local_admin") or context.credential_data
        if not creds or not creds.get("username"):
            return []

        username = creds["username"]
        password = creds.get("password", "")
        domain = creds.get("domain", "")

        writable = await asyncio.get_event_loop().run_in_executor(
            None, self._enumerate_shares, host.ip, username, password, domain
        )
        if not writable:
            return []

        share_list = "\n".join(
            f"  \\\\{host.ip}\\{s['name']}  ({s['access']})" for s in writable
        )
        return [FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="SMB Share With Write Access Identified",
            description=(
                f"{len(writable)} SMB share(s) were found to permit write access with "
                "the provided credentials. An attacker with these credentials could "
                "upload malicious executables or replace legitimate files."
            ),
            evidence=f"Writable shares on {host.ip}:\n{share_list}",
            remediation=(
                "Review share permissions and apply the principle of least privilege. "
                "Remove write access from shares that do not require it, and audit "
                "existing share contents for sensitive data."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1021/002/",
            ],
            port_number=445,
            protocol="tcp",
        )]

    def _enumerate_shares(
        self, ip: str, username: str, password: str, domain: str
    ) -> list[dict]:
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            logger.debug("impacket not available — skipping SMB share enumeration")
            return []

        writable: list[dict] = []
        try:
            conn = SMBConnection(ip, ip, timeout=8)
            conn.login(username, password, domain)
            shares = conn.listShares()
            for share in shares:
                name = share["shi1_netname"].decode("utf-16-le").rstrip("\x00")
                if name.upper() in ("IPC$",):
                    continue
                access = self._probe_share_access(conn, name)
                if access in ("WRITE", "READ,WRITE"):
                    writable.append({"name": name, "access": access})
            conn.logoff()
        except Exception as exc:
            logger.debug("SMB share enum failed for %s: %s", ip, exc)
        return writable

    def _probe_share_access(self, conn, share_name: str) -> str:
        try:
            tid = conn.connectTree(share_name)
            # Try creating a test file to verify write access
            test_name = "_scanr_write_test.tmp"
            try:
                fid = conn.createFile(tid, test_name)
                conn.closeFile(tid, fid)
                try:
                    conn.deleteFiles(tid, test_name)
                except Exception:
                    pass
                return "READ,WRITE"
            except Exception:
                return "READ"
        except Exception:
            return "NONE"
