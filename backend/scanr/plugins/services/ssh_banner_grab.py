"""SSH-on-any-port fallback.

The dedicated SSH plugins only run on the well-known SSH ports (22/2222/…), so
an SSH daemon on an unusual port is missed entirely — exactly the gap where
Nessus reported SSH and ScanR did not. This plugin banner-grabs every open TCP
port that nmap left unidentified (or already looks like SSH), detects SSH from
the `SSH-...` handshake banner, reports the exposure, and reuses the OpenSSH
version analysis so vulnerable daemons on odd ports are flagged too.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.ssh.ssh_version import SshVersionPlugin
from scanr.scanner.fingerprint.banner_grabber import grab_banner

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# Ports already fully covered by ssh.ssh_version — don't double-report.
_KNOWN_SSH_PORTS = {22, 2222, 2022, 22222}
_MAX_PROBES = 200      # cap per host so a huge open-port set can't blow up the scan
_CONCURRENCY = 20


class SshBannerGrabPlugin(PluginBase):
    id = "services.ssh_banner_grab"
    name = "SSH on Non-Standard Port"
    description = "Banner-grab open TCP ports to detect SSH running on non-standard ports"
    category = PluginCategory.services
    severity = Severity.low
    ports = None  # all ports

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        candidates: list[int] = []
        for p in host.ports:
            if p.state != "open" or p.number in _KNOWN_SSH_PORTS:
                continue
            svc = (p.service.name.lower() if p.service and p.service.name else "")
            # Only probe ports nmap left unidentified, or that already look like SSH —
            # no need to re-grab a known HTTP/SMTP/etc. service.
            if svc and "ssh" not in svc:
                continue
            candidates.append(p.number)
            if len(candidates) >= _MAX_PROBES:
                break
        if not candidates:
            return []

        sem = asyncio.Semaphore(_CONCURRENCY)

        async def probe(port: int) -> tuple[int, str | None]:
            async with sem:
                try:
                    return port, await grab_banner(host.ip, port)
                except Exception:  # noqa: BLE001 - a failed probe is not an error
                    return port, None

        results = await asyncio.gather(*[probe(p) for p in candidates])
        findings: list[FindingData] = []
        for port, banner in results:
            findings.extend(self._findings_for(host.ip, port, banner))
        return findings

    def _findings_for(self, ip: str, port: int, banner: str | None) -> list[FindingData]:
        """Pure detection/analysis for one probed port (no network)."""
        if not banner or not banner.startswith("SSH-"):
            return []
        banner = banner.strip()
        out: list[FindingData] = [
            FindingData(
                plugin_id=self.id,
                severity=Severity.low,
                title=f"SSH Service on Non-Standard Port {port}",
                description=(
                    f"An SSH daemon is exposed on port {port}, outside the usual SSH ports. "
                    "Non-standard SSH exposure is easy to overlook in firewall reviews and can "
                    "indicate shadow IT or a backdoor; it also widens the remote-login attack surface."
                ),
                evidence=f"{ip}:{port} banner: {banner}",
                remediation=(
                    "Confirm this SSH service is intended, restrict it to trusted networks, and "
                    "enforce key-based auth. Remove it if unexpected."
                ),
                references=["https://cwe.mitre.org/data/definitions/1327.html"],
                port_number=port,
                protocol="tcp",
            )
        ]
        # Reuse the OpenSSH/Dropbear version vulnerability analysis on this port.
        try:
            vf = SshVersionPlugin()._analyse_banner(banner, ip, port)
        except Exception:  # noqa: BLE001
            vf = None
        if vf is not None:
            out.append(FindingData(
                plugin_id=self.id,
                severity=vf.severity,
                title=vf.title,
                description=vf.description,
                evidence=vf.evidence,
                remediation=vf.remediation,
                references=list(vf.references),
                cve_ids=list(vf.cve_ids),
                cvss_score=vf.cvss_score,
                port_number=port,
                protocol="tcp",
            ))
        return out
