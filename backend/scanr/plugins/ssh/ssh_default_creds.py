"""SSH default credential check.

Tests a short list of common default SSH credentials.
Does NOT brute-force — strictly limited to known factory defaults.
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

DEFAULT_CREDS = [
    ("root", "root"),
    ("root", ""),
    ("root", "toor"),
    ("admin", "admin"),
    ("admin", "password"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
    ("cisco", "cisco"),
    ("vagrant", "vagrant"),
    ("test", "test"),
    ("user", "user"),
]


class SshDefaultCredsPlugin(PluginBase):
    id = "ssh.ssh_default_creds"
    name = "SSH Default Credentials"
    description = "Test common default SSH username/password pairs"
    category = PluginCategory.ssh
    severity = Severity.critical
    ports = [22, 2222]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in self.ports or port.state != "open":
                continue
            found = await self._try_creds(host.ip, port.number)
            for username, password in found:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title=f"SSH Default Credentials: {username}:{password or '(empty)'}",
                    description=(
                        f"Default SSH credentials were accepted. "
                        f"An attacker can gain shell access using {username}:{password or '(empty)'}."
                    ),
                    evidence=f"Successful SSH login to {host.ip}:{port.number} as {username}",
                    remediation="Change all default passwords immediately. Disable password authentication and use SSH keys.",
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _try_creds(self, ip: str, port: int) -> list[tuple[str, str]]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._ssh_sync, ip, port)

    def _ssh_sync(self, ip: str, port: int) -> list[tuple[str, str]]:
        import paramiko
        found = []
        for username, password in DEFAULT_CREDS:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    ip, port=port, username=username, password=password,
                    timeout=5, look_for_keys=False, allow_agent=False,
                    banner_timeout=5,
                )
                client.close()
                found.append((username, password))
                if found:
                    break  # stop after first success
            except paramiko.AuthenticationException:
                continue
            except Exception:
                break
        return found
