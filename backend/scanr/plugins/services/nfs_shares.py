"""NFS share enumeration.

Checks whether an NFS server exposes shares without requiring authentication,
which can allow any host on the network to mount and read or write the share.
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


class NfsSharesPlugin(PluginBase):
    id = "services.nfs_shares"
    name = "NFS Share Exposed"
    description = "Enumerate NFS exports and flag shares accessible without authentication"
    category = PluginCategory.services
    severity = Severity.high
    ports = [2049, 111]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number in (2049, 111) and p.state == "open" for p in host.ports):
            return []
        exports = await asyncio.get_running_loop().run_in_executor(
            None, self._showmount, host.ip
        )
        if not exports:
            return []

        export_list = "\n".join(f"  {e['path']}  {e['clients']}" for e in exports)
        return [FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="NFS Shares Accessible Without Authentication",
            description=(
                f"{len(exports)} NFS export(s) are available to unauthenticated clients. "
                "Any host matching the export ACL can mount the share and read or write "
                "files, potentially exposing sensitive data or allowing malicious file "
                "uploads."
            ),
            evidence=f"NFS exports on {host.ip}:\n{export_list}",
            remediation=(
                "Restrict NFS exports to specific trusted IP addresses or subnets in "
                "/etc/exports. Use 'no_root_squash' only where absolutely necessary, "
                "and prefer NFSv4 with Kerberos authentication (sec=krb5) for sensitive "
                "shares. Disable portmapper/rpcbind (port 111) if NFS is not required."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1135/",
                "https://www.sans.org/blog/nfs-security-best-practices/",
            ],
            port_number=2049,
            protocol="tcp",
        )]

    def _showmount(self, ip: str) -> list[dict]:
        """Run showmount -e equivalent using rpc calls, fall back to subprocess."""
        # Try subprocess showmount first (fastest, most reliable)
        exports = self._showmount_subprocess(ip)
        if exports is not None:
            return exports
        # Fallback: nmap script
        return self._showmount_nmap(ip)

    def _showmount_subprocess(self, ip: str) -> list[dict] | None:
        import subprocess
        import shutil
        if not shutil.which("showmount"):
            return None
        try:
            result = subprocess.run(
                ["showmount", "-e", "--no-headers", ip],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return []
            exports = []
            for line in result.stdout.strip().splitlines():
                parts = line.split(None, 1)
                if parts:
                    exports.append({
                        "path": parts[0],
                        "clients": parts[1] if len(parts) > 1 else "*",
                    })
            return exports
        except Exception as exc:
            logger.debug("showmount subprocess failed for %s: %s", ip, exc)
            return None

    def _showmount_nmap(self, ip: str) -> list[dict]:
        import subprocess
        import shutil
        if not shutil.which("nmap"):
            return []
        try:
            result = subprocess.run(
                ["nmap", "--script", "nfs-showmount", "-p", "111,2049", ip,
                 "--script-timeout", "10s", "-oN", "-"],
                capture_output=True, text=True, timeout=20
            )
            exports = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("/"):
                    parts = line.split(None, 1)
                    exports.append({
                        "path": parts[0],
                        "clients": parts[1] if len(parts) > 1 else "*",
                    })
            return exports
        except Exception as exc:
            logger.debug("nmap nfs-showmount failed for %s: %s", ip, exc)
            return []
