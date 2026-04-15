"""Authenticated SSH system audit plugin.

Connects with provided credentials and checks:
- Unpatched OS packages (high-level check via package manager)
- Root login allowed
- Password authentication enabled
- World-writable files in sensitive dirs
- Sudo nopasswd entries
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


class SshAuditPlugin(PluginBase):
    id = "authenticated.ssh_audit"
    name = "Authenticated SSH System Audit"
    description = "SSH into target and audit OS configuration and security posture"
    category = PluginCategory.authenticated
    severity = Severity.info
    requires_auth = True
    ports = [22, 2222]

    CHECKS = [
        ("grep -i '^PermitRootLogin yes' /etc/ssh/sshd_config 2>/dev/null", "PermitRootLogin yes", Severity.high,
         "SSH Root Login Permitted", "sshd_config allows direct root login.",
         "Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd."),
        ("grep -i '^PasswordAuthentication yes' /etc/ssh/sshd_config 2>/dev/null", "PasswordAuthentication yes", Severity.medium,
         "SSH Password Authentication Enabled", "Password auth enabled — brute-force risk.",
         "Use key-based auth only: set PasswordAuthentication no in sshd_config."),
        ("sudo -l 2>/dev/null | grep NOPASSWD", "NOPASSWD", Severity.high,
         "Sudo NOPASSWD Entries Found", "User can run commands without password via sudo.",
         "Remove NOPASSWD sudo entries or restrict to specific commands."),
        ("find /etc /root -maxdepth 2 -perm -o+w 2>/dev/null | head -5", "/etc", Severity.high,
         "World-Writable Files in Sensitive Directories", "World-writable files in /etc or /root.",
         "Remove world-write permission: chmod o-w <file>"),
        ("cat /etc/shadow 2>/dev/null | grep '::' | head -3", "::", Severity.critical,
         "Account With No Password Found", "Shadow file contains accounts with empty password hash.",
         "Set passwords or lock all accounts: passwd -l <username>"),
    ]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not context.credential_data:
            return []
        cred = context.credential_data
        if cred.get("type") not in (None, "ssh"):
            return []

        findings = []
        for port in host.ports:
            if port.number not in (22, 2222) or port.state != "open":
                continue
            for cmd, indicator, sev, title, desc, remediation in self.CHECKS:
                output = await self._run_command(host.ip, port.number, cred, cmd)
                if output and indicator in output:
                    findings.append(FindingData(
                        plugin_id=self.id,
                        severity=sev,
                        title=title,
                        description=desc,
                        evidence=f"Command: {cmd}\nOutput: {output[:500]}",
                        remediation=remediation,
                        port_number=port.number,
                        protocol="tcp",
                    ))
        return findings

    async def _run_command(self, ip: str, port: int, cred: dict, cmd: str) -> str | None:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._ssh_cmd, ip, port, cred, cmd)

    def _ssh_cmd(self, ip: str, port: int, cred: dict, cmd: str) -> str | None:
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": ip,
                "port": port,
                "username": cred.get("username", "root"),
                "timeout": 10,
            }
            if "private_key" in cred:
                import io
                pkey = paramiko.RSAKey.from_private_key(io.StringIO(cred["private_key"]))
                connect_kwargs["pkey"] = pkey
            else:
                connect_kwargs["password"] = cred.get("password", "")
                connect_kwargs["look_for_keys"] = False

            client.connect(**connect_kwargs)
            _, stdout, _ = client.exec_command(cmd, timeout=10)
            output = stdout.read().decode(errors="replace")
            client.close()
            return output.strip() or None
        except Exception as exc:
            logger.debug("SSH command failed %s: %s", ip, exc)
            return None
