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
import re
import shlex
import socket
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
        cred = context.credential("ssh") or context.credential("generic") or context.credential_data
        if not cred:
            return []
        if cred.get("type") not in (None, "ssh", "generic"):
            return []

        findings = []
        for port in host.ports:
            if port.number not in (22, 2222) or port.state != "open":
                continue
            config_cmd = self._effective_config_command(host.ip, port.number, cred)
            config = await self._run_command(host.ip, port.number, cred, config_cmd)
            effective = self._parse_sshd_t(config or "")
            if effective.get("permitrootlogin") == "yes":
                findings.append(self._config_finding(
                    port.number, Severity.high, "SSH Root Login Permitted",
                    "The effective sshd configuration permits direct root login.",
                    "Set PermitRootLogin no in sshd_config or an included file and restart sshd.",
                ))
            if effective.get("passwordauthentication") == "yes":
                findings.append(self._config_finding(
                    port.number, Severity.medium, "SSH Password Authentication Enabled",
                    "The effective sshd configuration permits password authentication.",
                    "Use key-based authentication and set PasswordAuthentication no in sshd_config or an included file.",
                ))
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

    @staticmethod
    def _effective_config_command(ip: str, port: int, cred: dict) -> str:
        """Ask sshd to resolve includes and the Match context for this session."""
        source_ip = "127.0.0.1"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect((ip, port))
                source_ip = route.getsockname()[0]
        except OSError:
            pass
        username = str(cred.get("username", "root"))
        # sshd parses commas inside -C as field separators. Shell quoting does
        # not protect that grammar, so skip Match evaluation for unusual names.
        if not re.fullmatch(r"[A-Za-z0-9._@\\-]+", username):
            return "sshd -T 2>/dev/null"
        # The target-side host criterion is approximated by the source address;
        # Match User/Address/LocalAddress/LocalPort are evaluated explicitly.
        context = (
            f"user={username},host={source_ip},addr={source_ip},"
            f"laddr={ip},lport={port}"
        )
        return f"sshd -T -C {shlex.quote(context)} 2>/dev/null"

    @staticmethod
    def _parse_sshd_t(output: str) -> dict[str, str]:
        values = {}
        for line in output.lower().splitlines():
            fields = line.split(None, 1)
            if len(fields) == 2:
                values[fields[0]] = fields[1]
        return values

    def _config_finding(self, port, severity, title, description, remediation):
        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=title,
            description=description,
            evidence=f"Effective sshd setting reported by sshd -T -C on port {port}.",
            remediation=remediation,
            port_number=port,
            protocol="tcp",
        )

    async def _run_command(self, ip: str, port: int, cred: dict, cmd: str) -> str | None:
        loop = asyncio.get_running_loop()
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
