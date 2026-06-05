from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class FtpAnonPlugin(PluginBase):
    id = "services.ftp_anon"
    name = "FTP Anonymous Access"
    description = "Test FTP server for anonymous login"
    category = PluginCategory.services
    severity = Severity.high
    ports = [21]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number != 21 or port.state != "open":
                continue
            accessible = await self._try_anon_ftp(host.ip, 21)
            if accessible:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="FTP Anonymous Login Allowed",
                    description="The FTP server allows anonymous access without authentication, exposing files to unauthenticated users.",
                    evidence=f"Anonymous FTP login succeeded on {host.ip}:21",
                    remediation="Disable anonymous FTP access. If required, restrict to read-only access on a dedicated directory.",
                    references=["https://cwe.mitre.org/data/definitions/284.html"],
                    port_number=21,
                    protocol="tcp",
                ))
        return findings

    async def _try_anon_ftp(self, ip: str, port: int) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._ftp_sync, ip, port)

    def _ftp_sync(self, ip: str, port: int) -> bool:
        import ftplib
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=5)
            ftp.login("anonymous", "scanr@example.com")
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False
        except Exception:
            return False
