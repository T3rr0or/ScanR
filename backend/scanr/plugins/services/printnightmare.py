"""PrintNightmare detection (CVE-2021-1675 / CVE-2021-34527).

Attempts a null-session RpcOpenPrinter call via impacket MS-RPRN.
If the spooler accepts the open without authentication, the host is potentially
vulnerable. Detection only — no driver installation, no exploitation.
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


class PrintNightmarePlugin(PluginBase):
    id = "services.printnightmare"
    name = "PrintNightmare (CVE-2021-1675 / CVE-2021-34527)"
    description = "Detect if Windows Print Spooler accepts unauthenticated RPC calls via null session (detection only)"
    category = PluginCategory.services
    severity = Severity.critical
    cve_ids = ["CVE-2021-1675", "CVE-2021-34527"]
    ports = [445]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 445 and p.state == "open" for p in host.ports):
            return []
        # Only Windows hosts are vulnerable to PrintNightmare.
        # Skip if either os_family or os_name is positively identified as non-Windows.
        # When both are empty (OS unknown) we still probe — better a FP than a FN on a real Windows host.
        os_family = (host.os_family or "").lower()
        os_name = (host.os_name or "").lower()
        known_os = os_family or os_name
        if known_os and "windows" not in known_os:
            return []
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self._probe, host.ip)
        return [result] if result else []

    def _probe(self, ip: str) -> FindingData | None:
        try:
            from impacket.dcerpc.v5 import transport, rprn
        except ImportError:
            logger.debug("impacket not available — printnightmare plugin skipped")
            return None

        try:
            string_binding = f"ncacn_np:{ip}[\\pipe\\spoolss]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_connect_timeout(8)

            # Null session (no credentials)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)

            # Attempt to open printer — read-only, detection only
            resp = rprn.hRpcOpenPrinter(dce, f"\\\\{ip}\x00")
            handle = resp["pHandle"]

            # Got a handle → spooler accepts null session
            # Close it immediately (no write operations)
            try:
                rprn.hRpcClosePrinter(dce, handle)
            except Exception:
                pass
            dce.disconnect()

            return FindingData(
                plugin_id=self.id,
                severity=Severity.critical,
                title="PrintNightmare — Windows Print Spooler Accepts Unauthenticated RPC",
                description=(
                    f"The Windows Print Spooler on {ip} accepted an unauthenticated RPC connection "
                    "via null session (SMB named pipe \\\\PIPE\\\\spoolss). "
                    "CVE-2021-1675 and CVE-2021-34527 allow any authenticated user to load a "
                    "malicious printer driver and achieve SYSTEM-level code execution. "
                    "Null-session access means authentication is not even required on this host."
                ),
                evidence=(
                    f"RPC transport: ncacn_np:{ip}[\\pipe\\spoolss]\n"
                    "Authentication: NULL session (no credentials)\n"
                    f"hRpcOpenPrinter(\\\\{ip}) returned a valid handle"
                ),
                remediation=(
                    "Disable the Print Spooler service if printing is not required: "
                    "Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled. "
                    "If printing is required, apply Microsoft patch KB5004945 (or later CU). "
                    "Block inbound SMB (port 445) from untrusted networks."
                ),
                references=[
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                ],
                port_number=445,
                protocol="tcp",
            )

        except Exception as exc:
            err_str = str(exc).lower()
            # "access denied" or "wrong credentials" means service exists but auth required
            if "access_denied" in err_str or "logon_failure" in err_str:
                logger.debug("PrintNightmare: %s requires auth — not vulnerable via null session", ip)
            else:
                logger.debug("PrintNightmare probe failed on %s: %s", ip, exc)
        return None
