"""Exim MTA version check for known-exploited SMTP vulnerabilities.

Exim announces itself in the SMTP greeting — ``220 host ESMTP Exim 4.90_1 ...``
— so its version is readable before any command is sent. Several Exim flaws are
in CISA's Known Exploited Vulnerabilities catalog and are reachable from that
same unauthenticated SMTP surface, but ScanR's NVD matcher never fired on them
because nmap rarely attaches a ``product/version`` to port 25. This plugin reads
the greeting, parses the Exim version, and compares it against the fixed
versions published in the CVE and vendor advisories.

It sends nothing but a banner read (and a courtesy QUIT); no command is issued
to the MTA, so it neither relays nor probes mail. Version boundaries come from
the public advisories cited per finding, not from any third-party scanner.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.scanner.fingerprint.banner_grabber import grab_banner

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

SMTP_PORTS = [25, 465, 587]

# "220-mail ESMTP Exim 4.90_1 Ubuntu ..." — Exim uses '_' for security releases
# (4.90_1 == 4.90.1). Capture the dotted/underscored version token only.
_EXIM_RE = re.compile(r"\bExim\s+(\d+\.\d+(?:[._]\d+)*)", re.I)


@dataclass(frozen=True)
class _Vuln:
    cve: str
    # affected when introduced <= version < fixed  (introduced None = "any older")
    introduced: tuple[int, ...] | None
    fixed: tuple[int, ...]
    severity: Severity
    summary: str
    reference: str


# Version boundaries are from the CVE records and the Exim advisories, not from
# any proprietary plugin feed.
_VULNS: tuple[_Vuln, ...] = (
    _Vuln(
        cve="CVE-2010-4344",
        introduced=None,
        fixed=(4, 70),
        severity=Severity.critical,
        summary="Heap overflow in string_format() (string.c), remotely exploitable for RCE.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2010-4344",
    ),
    _Vuln(
        cve="CVE-2018-6789",
        introduced=None,
        fixed=(4, 90, 1),
        severity=Severity.critical,
        summary="Off-by-one/buffer overflow in the base64d() SMTP decoder, pre-auth RCE.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2018-6789",
    ),
    _Vuln(
        cve="CVE-2019-10149",
        introduced=(4, 87),
        fixed=(4, 92),
        severity=Severity.critical,
        summary='"Return of the WIZard" — deliver_message() command injection, remote RCE as root.',
        reference="https://nvd.nist.gov/vuln/detail/CVE-2019-10149",
    ),
    _Vuln(
        cve="CVE-2019-16928",
        introduced=(4, 92),
        fixed=(4, 92, 3),
        severity=Severity.high,
        summary="Heap overflow in string_vformat() reachable via a long EHLO argument.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2019-16928",
    ),
)


def _parse_version(token: str) -> tuple[int, ...] | None:
    """Turn '4.90_1' / '4.92.2' into (4, 90, 1) / (4, 92, 2)."""
    parts = re.split(r"[._]", token)
    out: list[int] = []
    for p in parts:
        if not p.isdigit():
            break
        out.append(int(p))
    return tuple(out) or None


def _applies(version: tuple[int, ...], v: _Vuln) -> bool:
    if version >= v.fixed:
        return False
    if v.introduced is not None and version < v.introduced:
        return False
    return True


def analyse_banner(banner: str, ip: str, port: int, plugin_id: str) -> FindingData | None:
    """Pure detection: given an SMTP banner, return a finding or None. No I/O."""
    if not banner:
        return None
    match = _EXIM_RE.search(banner)
    if not match:
        return None
    raw = match.group(1)
    version = _parse_version(raw)
    if version is None:
        return None

    hits = [v for v in _VULNS if _applies(version, v)]
    if not hits:
        return None

    severity = Severity.critical if any(v.severity is Severity.critical for v in hits) else Severity.high
    cve_ids = [v.cve for v in hits]
    lines = "\n".join(f"  - {v.cve}: {v.summary}" for v in hits)
    references = sorted({v.reference for v in hits}) + [
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ]

    return FindingData(
        plugin_id=plugin_id,
        severity=severity,
        title=f"Exim {raw} — Known-Exploited Vulnerabilities",
        description=(
            f"The SMTP service on port {port} runs Exim {raw}, which predates the fix for one or more "
            "vulnerabilities in CISA's Known Exploited Vulnerabilities catalog:\n"
            f"{lines}\n\n"
            "These are reachable from the unauthenticated SMTP surface and have been used for remote "
            "code execution, in several cases as root."
        ),
        evidence=f"{ip}:{port} SMTP banner: {banner.strip()[:200]}",
        remediation=(
            "Upgrade Exim to the current stable release (at minimum 4.92.3 to clear these specific CVEs, "
            "and ideally the latest 4.9x) and confirm the distribution's security backports are applied. "
            "Restrict inbound SMTP to expected relays where the service is not meant to be public."
        ),
        references=references,
        cve_ids=cve_ids,
        port_number=port,
        protocol="tcp",
    )


class EximVersionPlugin(PluginBase):
    id = "services.exim_version"
    name = "Exim Vulnerable Version"
    description = "Detect Exim MTA versions affected by known-exploited SMTP vulnerabilities"
    category = PluginCategory.services
    severity = Severity.critical
    cve_ids = ["CVE-2010-4344", "CVE-2018-6789", "CVE-2019-10149", "CVE-2019-16928"]
    ports = SMTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.state != "open" or port.number not in SMTP_PORTS:
                continue
            banner = (port.banner or "").strip()
            if "exim" not in banner.lower():
                # nmap may not have kept the greeting; read it directly.
                banner = (await grab_banner(host.ip, port.number, use_ssl=(port.number == 465))) or ""
            finding = analyse_banner(banner, host.ip, port.number, self.id)
            if finding:
                findings.append(finding)
        return findings
