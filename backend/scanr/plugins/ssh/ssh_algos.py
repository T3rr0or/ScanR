from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

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
        return findings

    async def _get_ssh_algos(self, ip: str, port: int) -> dict | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._ssh_sync, ip, port)

    def _ssh_sync(self, ip: str, port: int) -> dict | None:
        try:
            import socket
            import paramiko
            transport = paramiko.Transport(socket.create_connection((ip, port), timeout=5))
            transport.start_client(timeout=5)
            security_options = transport.get_security_options()
            algos = {
                "kex_algorithms": list(security_options.kex),
                "encryption_algorithms_server_to_client": list(security_options.ciphers),
                "mac_algorithms_server_to_client": list(security_options.digests),
            }
            transport.close()
            return algos
        except Exception as exc:
            logger.debug("SSH algo check failed %s:%d: %s", ip, port, exc)
            return None
