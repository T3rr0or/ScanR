"""SSH default credential check.

Tests a short list of common default SSH credentials, or a custom wordlist
when one is configured in the scan profile's brute_force section.
Does NOT brute-force uncontrolled lists — bounded by max_failures_per_account.
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
        cfg = context.get_brute_config()
        cred_wl_id = cfg.get("credential_wordlist_id")
        username_wl_id = cfg.get("username_wordlist_id")
        password_wl_id = cfg.get("password_wordlist_id")

        for port in host.ports:
            if port.number not in self.ports or port.state != "open":
                continue

            if cred_wl_id:
                # Use credential pairs wordlist
                pairs = list(context.iter_credential_pairs(cred_wl_id))
            elif username_wl_id and password_wl_id:
                # Cartesian product of user × pass lists (bounded)
                usernames = list(context.iter_wordlist(username_wl_id))[:200]
                passwords = list(context.iter_wordlist(password_wl_id))[:200]
                pairs = [(u, p) for u in usernames for p in passwords]
            else:
                # Fall back to built-in defaults
                pairs = DEFAULT_CREDS

            max_failures = cfg.get("max_failures_per_account", 5)
            delay_s = cfg.get("delay_ms", 0) / 1000.0
            stop_on_success = cfg.get("stop_on_success", True)

            found = await self._try_creds_list(host.ip, port.number, pairs, max_failures, delay_s)
            for username, password in found:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title=f"SSH Valid Credentials: {username}:{password or '(empty)'}",
                    description=(
                        f"SSH credentials were accepted on {host.ip}:{port.number}. "
                        f"An attacker can gain shell access using {username}:{password or '(empty)'}."
                    ),
                    evidence=f"Successful SSH login to {host.ip}:{port.number} as {username}",
                    remediation="Change all default passwords immediately. Disable password authentication and use SSH keys.",
                    port_number=port.number,
                    protocol="tcp",
                ))
                if stop_on_success:
                    break
        return findings

    async def _try_creds_list(self, ip: str, port: int, pairs: list, max_failures: int, delay_s: float) -> list[tuple[str, str]]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._ssh_sync_list, ip, port, pairs, max_failures, delay_s)

    def _ssh_sync_list(self, ip: str, port: int, pairs: list, max_failures: int, delay_s: float) -> list[tuple[str, str]]:
        import paramiko
        import time
        found = []
        failures = 0
        for username, password in pairs:
            if failures >= max_failures:
                break
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
                return found  # stop on first success
            except paramiko.AuthenticationException:
                failures += 1
                if delay_s > 0:
                    time.sleep(delay_s)
                continue
            except Exception:
                break
        return found
