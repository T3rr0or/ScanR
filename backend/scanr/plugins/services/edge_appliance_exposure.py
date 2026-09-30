"""Fingerprint internet-facing edge appliance management interfaces.

Appliance web VIPs often omit product/version data from ordinary service
fingerprints. This plugin uses product-specific HTTP markers to identify
reachable management surfaces and points operators to the vendor advisories.

This plugin identifies the appliance from stable, product-specific markers
(login-page assets, server headers, titles) and reports the exposed management
surface. A product fingerprint alone cannot establish whether a particular CVE
affects the installed model and build, so it does not report CVE identifiers.
It only issues GETs and matches on server-emitted content; it sends no exploit
payload.

Citrix/NetScaler is intentionally not here — it has its own dedicated plugin.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

APPLIANCE_PORTS = [443, 80, 8080, 8443, 4343, 10443]
_HTTPS_PORTS = {443, 8443, 4343, 10443}


@dataclass(frozen=True)
class _Signature:
    key: str
    name: str
    paths: tuple[str, ...]
    # Lowercased substrings; any one present in body or Server header confirms.
    markers: tuple[str, ...]
    severity: Severity
    note: str
    remediation: str
    references: tuple[str, ...]
    version_res: tuple[re.Pattern[str], ...] = field(default_factory=tuple)


SIGNATURES: tuple[_Signature, ...] = (
    _Signature(
        key="sonicwall_sma",
        name="SonicWall SMA / SRA SSL-VPN",
        paths=("/cgi-bin/welcome", "/__api__/v1/logon", "/"),
        markers=("sonicwall", "sslvpn", "virtual office", "sonicwall ssl-vpn"),
        severity=Severity.high,
        note=(
            "A SonicWall SMA/SRA SSL-VPN appliance fronts remote access to the internal network. This product "
            "line has multiple known-exploited pre-auth vulnerabilities (SQL injection and appliance takeover), "
            "several used by ransomware operators."
        ),
        remediation=(
            "Apply the current SonicWall firmware for the SMA/SRA model, rotate credentials and enable MFA, and "
            "restrict management access. Retire end-of-life SRA hardware, which no longer receives fixes."
        ),
        references=("https://psirt.global.sonicwall.com/vuln-list",),
    ),
    _Signature(
        key="ivanti_csa",
        name="Ivanti Cloud Services Appliance (CSA)",
        paths=("/client/index.php", "/gsb/", "/"),
        markers=("cloud services appliance", "ivanti", "landesk"),
        severity=Severity.high,
        note=(
            "An Ivanti Cloud Services Appliance is exposed. The CSA has a cluster of known-exploited "
            "vulnerabilities (command injection and authentication bypass) chained for remote code execution; "
            "Ivanti's guidance is that CSA 4.6 is end-of-life and should be replaced."
        ),
        remediation=(
            "Move to CSA 5.0 on supported firmware, or take the appliance off the internet. Apply the current "
            "Ivanti security advisories and review the appliance for signs of compromise."
        ),
        references=("https://forums.ivanti.com/s/product-security",),
    ),
    _Signature(
        key="watchguard_firebox",
        name="WatchGuard Firebox",
        paths=("/", "/wgcgi.cgi", "/auth/login"),
        markers=("fireware", "watchguard", "firebox"),
        severity=Severity.medium,
        note=(
            "A WatchGuard Firebox management or SSL-VPN surface is reachable. Fireware has known-exploited "
            "vulnerabilities in its IKE/authentication handling that lead to remote code execution on the "
            "firewall itself."
        ),
        remediation=(
            "Upgrade Fireware to the fixed release in WatchGuard's advisory, restrict management and SSL-VPN to "
            "trusted networks, and enable MFA on remote access."
        ),
        references=("https://www.watchguard.com/wgrd-psirt",),
    ),
    _Signature(
        key="zyxel_fw",
        name="Zyxel Firewall / NAS",
        paths=("/", "/ext-js/index.html", "/cgi-bin/zyxel"),
        markers=("zyxel", "usg flex", "zyxel nas", "zld"),
        severity=Severity.medium,
        note=(
            "A Zyxel firewall or NAS web interface is exposed. Multiple Zyxel appliances have known-exploited "
            "pre-auth command-injection and buffer-overflow vulnerabilities used to build botnets."
        ),
        remediation=(
            "Apply the current Zyxel firmware, disable WAN-side management, and restrict the web interface to "
            "trusted networks."
        ),
        references=("https://www.zyxel.com/global/en/support/security-advisories",),
    ),
    _Signature(
        key="vmware_vcenter",
        name="VMware vCenter Server",
        paths=("/", "/ui/", "/websso/SAML2/SSO/vsphere.local"),
        markers=("vsphere", "vcenter", "vmware", "getvcdetails", "websso"),
        severity=Severity.high,
        note=(
            "A VMware vCenter Server management interface is reachable. vCenter has repeated known-exploited "
            "pre-auth remote-code-execution and privilege-escalation vulnerabilities; it controls the entire "
            "virtual estate, so exposure to untrusted networks is high risk."
        ),
        remediation=(
            "Apply the current VMware (Broadcom) security advisory patches for vCenter, and keep the management "
            "interface on an isolated management network — never internet-facing."
        ),
        references=("https://www.broadcom.com/support/vmware-security-advisories",),
        version_res=(re.compile(r"vcenter[^0-9]{0,20}(\d+\.\d+\.\d+)", re.I),),
    ),
)


def _client(context: "ScanContext") -> httpx.AsyncClient:
    """Client factory so tests can swap in an httpx.MockTransport."""
    return httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=False, **context.proxy_config())


def _scheme(port: int) -> str:
    return "https" if port in _HTTPS_PORTS else "http"


def match_signature(sig: _Signature, body: str, server: str) -> str | None:
    """Return the marker that confirmed the product, or None. Pure."""
    hay = f"{body}\n{server}".lower()
    return next((m for m in sig.markers if m in hay), None)


def extract_version(sig: _Signature, body: str) -> str | None:
    for pattern in sig.version_res:
        m = pattern.search(body)
        if m:
            return m.group(1)
    return None


class EdgeApplianceExposurePlugin(PluginBase):
    id = "services.edge_appliance_exposure"
    name = "Edge Appliance Exposure"
    description = "Fingerprint exposed SonicWall, Ivanti, WatchGuard, Zyxel and vCenter management interfaces"
    category = PluginCategory.services
    severity = Severity.high
    ports = APPLIANCE_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.state != "open" or port.number not in APPLIANCE_PORTS:
                continue
            findings.extend(await self._probe(context, host.ip, port.number))
        return findings

    async def _get(self, context, url: str):
        try:
            async with _client(context) as client:
                return await client.get(url)
        except Exception:
            return None

    async def _probe(self, context, ip: str, port: int) -> list[FindingData]:
        base = f"{_scheme(port)}://{ip}:{port}"
        out: list[FindingData] = []
        seen: set[str] = set()

        for sig in SIGNATURES:
            if sig.key in seen:
                continue
            for path in sig.paths:
                resp = await self._get(context, base + path)
                if resp is None:
                    continue
                body = resp.text[:20000]
                server = resp.headers.get("server", "")
                marker = match_signature(sig, body, server)
                if not marker:
                    continue

                seen.add(sig.key)
                version = extract_version(sig, body)
                title = f"{sig.name} exposed" + (f" — version {version}" if version else "")
                evidence = f"GET {base}{path} -> HTTP {resp.status_code}, matched '{marker}'"
                if version:
                    evidence += f"; version disclosed: {version}"

                out.append(FindingData(
                    plugin_id=self.id,
                    severity=sig.severity,
                    title=title,
                    description=(
                        f"{sig.note}\n\nReachable at {base}{path}. This fingerprint does not identify the "
                        "exact model or firmware build, so check the vendor advisories for vulnerabilities that "
                        "apply to the installed version."
                    ),
                    evidence=evidence,
                    remediation=sig.remediation,
                    references=list(sig.references),
                    cve_ids=[],
                    port_number=port,
                    protocol="tcp",
                ))
                break  # one finding per appliance per port
        return out
