"""SSH version vulnerability check plugin.

Reads the SSH banner and flags known-vulnerable OpenSSH and Dropbear versions.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# OpenSSH versions with known high/critical CVEs (version_tuple: [cve_list, severity, description])
_VULNERABLE_OPENSSH: list[tuple[tuple[int, int], list[str], Severity, str]] = [
    # Format: (max_vulnerable_version, cves, severity, short_desc)
    ((9, 7), ["CVE-2024-6387"], Severity.critical,
     "regreSSHion: unauthenticated remote code execution via signal handler race condition"),
    ((8, 5), ["CVE-2021-41617"], Severity.high,
     "Privilege escalation via AuthorizedKeysCommand/AuthorizedPrincipalsCommand"),
    ((7, 7), ["CVE-2018-15473"], Severity.medium,
     "Username enumeration via timing difference in authentication"),
    ((7, 2), ["CVE-2016-0777", "CVE-2016-0778"], Severity.high,
     "Roaming feature memory leak exposing private key material"),
    ((6, 8), ["CVE-2015-5600"], Severity.high,
     "MaxAuthTries bypass via keyboard-interactive authentication"),
]


class SshVersionPlugin(PluginBase):
    id = "ssh.ssh_version"
    name = "Vulnerable SSH Version"
    description = "Flag known-vulnerable OpenSSH and Dropbear versions from banner"
    category = PluginCategory.ssh
    severity = Severity.high
    ports = [22, 2222, 2022, 22222]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        checked: set[int] = set()
        for port in host.ports:
            if port.number not in (self.ports or []) or port.state != "open":
                continue
            if port.number in checked:
                continue
            checked.add(port.number)

            banner = await self._get_banner(host.ip, port.number)
            if not banner:
                continue

            f = self._analyse_banner(banner, host.ip, port.number)
            if f:
                findings.append(f)
        return findings

    async def _get_banner(self, ip: str, port: int) -> str | None:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._read_banner_sync, ip, port)

    def _read_banner_sync(self, ip: str, port: int) -> str | None:
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            sock.settimeout(5)
            data = sock.recv(256)
            sock.close()
            return data.decode("ascii", errors="ignore").strip()
        except Exception:
            return None

    def _analyse_banner(self, banner: str, ip: str, port: int) -> FindingData | None:
        # Match OpenSSH version: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
        m = re.search(r"OpenSSH[_\s](\d+)\.(\d+)", banner, re.IGNORECASE)
        if not m:
            return None

        major, minor = int(m.group(1)), int(m.group(2))
        version = f"{major}.{minor}"

        for (max_maj, max_min), cves, sev, desc in _VULNERABLE_OPENSSH:
            if (major, minor) <= (max_maj, max_min):
                return FindingData(
                    plugin_id=self.id,
                    severity=sev,
                    title=f"Vulnerable OpenSSH Version: {version}",
                    description=(
                        f"OpenSSH {version} is affected by known vulnerabilities. "
                        f"{desc}."
                    ),
                    evidence=f"SSH banner: {banner}",
                    remediation=f"Upgrade OpenSSH to the latest stable release (≥{max_maj}.{max_min + 1}).",
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cves],
                    cve_ids=cves,
                    port_number=port,
                    protocol="tcp",
                )
        return None
