from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.ssh._kexinit import read_server_kexinit

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "gss-gex-sha1-", "gss-group1-sha1-"}
WEAK_CIPHERS = {"3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-32@openssh.com"}


class SshAlgosPlugin(PluginBase):
    id = "ssh.ssh_algos"
    name = "Weak SSH Algorithms"
    description = "Detect weak KEX, cipher, and MAC algorithms in SSH configuration"
    category = PluginCategory.ssh
    severity = Severity.medium
    ports = [22, 2222]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in (22, 2222) or port.state != "open":
                continue
            algos = await self._get_ssh_algos(host.ip, port.number)
            if not algos:
                continue

            weak_kex = [a for a in algos.get("kex_algorithms", []) if any(w in a for w in WEAK_KEX)]
            weak_ciphers = [a for a in algos.get("encryption_algorithms_server_to_client", []) if a in WEAK_CIPHERS]
            weak_macs = [a for a in algos.get("mac_algorithms_server_to_client", []) if a in WEAK_MACS]
            if weak_kex:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Weak SSH Key Exchange Algorithms",
                    description="The SSH server supports weak KEX algorithms vulnerable to cryptographic attacks.",
                    evidence=f"Weak KEX: {', '.join(weak_kex)}",
                    remediation="Remove SHA-1 and diffie-hellman-group1-sha1 KEX algorithms from sshd_config.",
                    port_number=port.number,
                    protocol="tcp",
                ))
            if weak_ciphers:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Weak SSH Encryption Ciphers",
                    description="The SSH server supports deprecated or weak encryption ciphers.",
                    evidence=f"Weak ciphers: {', '.join(weak_ciphers)}",
                    remediation="Configure sshd to use only AES-GCM and ChaCha20 ciphers.",
                    port_number=port.number,
                    protocol="tcp",
                ))
            if weak_macs:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Weak SSH Message Authentication Codes",
                    description="The SSH server supports deprecated or weak MAC algorithms.",
                    evidence=f"Weak MACs: {', '.join(weak_macs)}",
                    remediation="Remove MD5, truncated SHA-1, and 32-bit UMAC algorithms from sshd_config.",
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _get_ssh_algos(self, ip: str, port: int) -> dict | None:
        """Read the server's advertised algorithms from its KEXINIT.

        paramiko.get_security_options() returns the *client's* preferences, not
        the server's, so a check built on it reports our own configuration back
        at us. The shared reader parses the raw KEXINIT packet instead.
        """
        loop = asyncio.get_running_loop()
        kexinit = await loop.run_in_executor(None, read_server_kexinit, ip, port)
        if kexinit is None:
            return None
        return {
            "kex_algorithms": kexinit.kex_algorithms,
            "encryption_algorithms_server_to_client": kexinit.encryption_s2c,
            "mac_algorithms_server_to_client": kexinit.mac_s2c,
        }
