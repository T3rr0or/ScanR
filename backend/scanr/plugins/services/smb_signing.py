"""SMB signing disabled check.

Checks whether the SMB server requires message signing. Without signing,
the server is vulnerable to NTLM relay attacks.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class SmbSigningPlugin(PluginBase):
    id = "services.smb_signing"
    name = "SMB Signing Disabled"
    description = "Check if SMB signing is required (disabled = relay attack risk)"
    category = PluginCategory.services
    severity = Severity.medium
    ports = [445, 139]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in (445, 139) or port.state != "open":
                continue
            signing_required = await self._check_smb_signing(host.ip, port.number)
            if signing_required is False:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="SMB Signing Not Required",
                    description=(
                        "SMB signing is not required on this host. "
                        "This makes it vulnerable to NTLM relay attacks where an attacker can "
                        "intercept and relay authentication to gain unauthorized access."
                    ),
                    evidence=f"SMB negotiate response on port {port.number} shows SecurityMode without signing required flag",
                    remediation="Enable SMB signing: set 'RequireSecuritySignature = 1' in registry or via GPO (Microsoft Network Server: Digitally sign communications).",
                    references=[
                        "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always",
                    ],
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _check_smb_signing(self, ip: str, port: int) -> bool | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._smb_sync, ip, port)

    def _smb_sync(self, ip: str, port: int) -> bool | None:
        """Return True if signing required, False if not, None on error."""
        try:
            # SMB2 negotiate request (as hex string to avoid byte literal concat issues)
            smb2_negotiate = bytes.fromhex(
                "00000090"      # NetBIOS session length
                "fe534d42"      # SMB2 magic (\xfeSMB)
                "4000"          # struct size
                "0000"          # credit charge
                "00000000"      # status
                "0000"          # command: negotiate
                "0000"          # credits
                "00000000"      # flags
                "00000000"      # next command
                + "00" * 8      # message ID
                + "00" * 4      # process ID
                + "00" * 4      # tree ID
                + "00" * 8      # session ID
                + "00" * 16     # signature
                + "2400"        # negotiate body struct size
                + "0200"        # dialect count = 2
                + "0000"        # security mode
                + "0000"        # reserved
                + "00000000"    # capabilities
                + "00" * 16     # client GUID
                + "00000000"    # negotiate context
                + "0202"        # SMB 2.0.2
                + "1002"        # SMB 2.1
            )
            sock = socket.create_connection((ip, port), timeout=5)
            sock.send(smb2_negotiate)
            resp = sock.recv(1024)
            sock.close()
            # SecurityMode byte in SMB2 negotiate response (offset 70)
            if len(resp) > 72:
                security_mode = resp[70]
                # bit 1 = signing required
                return bool(security_mode & 0x02)
            return None
        except Exception:
            return None
