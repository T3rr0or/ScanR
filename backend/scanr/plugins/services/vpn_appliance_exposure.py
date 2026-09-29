"""SSL-VPN and remote-access appliance exposure.

Edge appliances are the most consistently exploited class of internet-facing
asset. They terminate untrusted traffic by design, they run vendor firmware on a
release cadence nobody controls, and a pre-authentication flaw in one is worth a
domain: Ivanti Connect Secure, Fortinet FortiOS, Palo Alto GlobalProtect, Cisco
ASA WebVPN and SonicWall SMA have each contributed mass-exploited,
actively-abused CVEs.

ScanR fingerprinted Citrix ADC already; this covers the rest of the set. It
identifies the product from markers the appliance itself serves, and extracts a
version when the appliance discloses one, so ``cve.cve_matcher`` and the report's
patch narrative have something concrete to work from.

GET requests only. The plugin never posts to a logon endpoint, never submits a
credential, and never touches the ``/dana-na/`` or ``/remote/`` paths associated
with known exploit chains beyond reading the login page every browser sees.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.services._pentest_common import _http_get, _open

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

VPN_PORTS = {443, 4443, 8443, 10443, 4433, 8444}


@dataclass(frozen=True)
class Appliance:
    """One product's fingerprint: where to look, what proves it, what to say."""

    vendor: str
    product: str
    paths: tuple[str, ...]
    body_markers: tuple[str, ...] = ()
    header_markers: tuple[tuple[str, str], ...] = ()
    cookie_markers: tuple[str, ...] = ()
    version_patterns: tuple[re.Pattern[str], ...] = ()
    notable_cves: tuple[str, ...] = ()
    advisory: str = ""
    notes: str = ""
    # Redirect targets are often the only tell on an appliance that serves a
    # bare 302 from "/".
    location_markers: tuple[str, ...] = ()


APPLIANCES: tuple[Appliance, ...] = (
    Appliance(
        vendor="Ivanti",
        product="Connect Secure / Policy Secure (formerly Pulse Secure)",
        paths=("/dana-na/auth/url_default/welcome.cgi", "/dana-na/", "/"),
        body_markers=(
            "/dana-na/",
            "welcome.cgi?p=",
            "pulse secure",
            "ivanti connect secure",
            "dsid_",
        ),
        cookie_markers=("dsid", "dssignin", "dslastaccess"),
        location_markers=("/dana-na/auth/url_default/welcome.cgi",),
        version_patterns=(
            re.compile(r"(?:Connect\s+Secure|Pulse\s+Connect\s+Secure|Ivanti)[^0-9]{0,20}(\d+\.\d+(?:R\d+(?:\.\d+)?)?)", re.I),
            re.compile(r"/dana-na/[^\"'\s]*\?[^\"'\s]*v=(\d+\.\d+[^\"'&\s]*)", re.I),
        ),
        notable_cves=("CVE-2023-46805", "CVE-2024-21887", "CVE-2024-21893", "CVE-2025-0282"),
        advisory="https://forums.ivanti.com/s/known-issues",
        notes=(
            "Ivanti Connect Secure has carried several pre-authentication "
            "authentication-bypass and command-injection chains that were exploited "
            "at scale within days of disclosure, including by state-linked actors. "
            "Appliance compromise has repeatedly survived patching, so a device that "
            "was exposed during a known exploitation window needs integrity "
            "verification, not just an update."
        ),
    ),
    Appliance(
        vendor="Fortinet",
        product="FortiGate SSL-VPN / FortiOS",
        paths=("/remote/login", "/remote/info", "/"),
        body_markers=(
            "/remote/login",
            "fortigate",
            "sslvpn_login",
            "fgt_lang",
            "f_action=",
            "/sslvpn/portal.html",
        ),
        header_markers=(("server", "xxxxxxxx-xxxxx"),),
        cookie_markers=("svpncookie", "apsc0okie"),
        location_markers=("/remote/login",),
        version_patterns=(
            re.compile(r"/sslvpn/[^\"'\s]*\?[^\"'\s]*ver=(\d+\.\d+\.\d+)", re.I),
            re.compile(r"FortiOS[^0-9]{0,12}(\d+\.\d+\.\d+)", re.I),
            re.compile(r"\"?fgt_version\"?\s*[:=]\s*\"?(\d+\.\d+\.\d+)", re.I),
        ),
        notable_cves=("CVE-2018-13379", "CVE-2022-42475", "CVE-2023-27997", "CVE-2024-21762"),
        advisory="https://www.fortiguard.com/psirt",
        notes=(
            "FortiOS SSL-VPN has produced repeated pre-authentication heap overflows "
            "reachable by an unauthenticated request, plus the path-traversal "
            "credential leak (CVE-2018-13379) whose harvested credentials are still "
            "circulating. Credentials taken during that window remain valid until "
            "they are individually reset."
        ),
    ),
    Appliance(
        vendor="Palo Alto Networks",
        product="GlobalProtect Portal / Gateway (PAN-OS)",
        paths=("/global-protect/login.esp", "/php/login.php", "/"),
        body_markers=(
            "global-protect",
            "globalprotect portal",
            "/global-protect/portal",
            "pan-os",
            "gp-portal",
        ),
        location_markers=("/global-protect/login.esp", "/php/login.php"),
        version_patterns=(
            re.compile(r"/global-protect/[^\"'\s]*\?[^\"'\s]*version=(\d+\.\d+(?:\.\d+)*)", re.I),
            re.compile(r"PAN-OS[^0-9]{0,12}(\d+\.\d+(?:\.\d+)*)", re.I),
        ),
        notable_cves=("CVE-2024-3400", "CVE-2021-3064", "CVE-2020-2021"),
        advisory="https://security.paloaltonetworks.com/",
        notes=(
            "CVE-2024-3400 was an unauthenticated command injection in the "
            "GlobalProtect feature, exploited in the wild before a patch existed, "
            "giving root on the firewall itself — the device enforcing the network's "
            "segmentation."
        ),
    ),
    Appliance(
        vendor="Cisco",
        product="ASA / Firepower WebVPN (AnyConnect)",
        paths=("/+CSCOE+/logon.html", "/+CSCOE+/portal.html", "/"),
        body_markers=("+cscoe+", "+cscou+", "anyconnect", "webvpn", "cisco secure client"),
        cookie_markers=("webvpn", "webvpncontext", "webvpnlogin"),
        location_markers=("/+CSCOE+/logon.html",),
        version_patterns=(
            re.compile(r"/\+CSCO[A-Z]\+/[^\"'\s]*\?[^\"'\s]*v=(\d+\.\d+[^\"'&\s]*)", re.I),
            re.compile(r"(?:ASA|Adaptive Security Appliance)[^0-9]{0,16}(\d+\.\d+\(\d+\)\d*)", re.I),
        ),
        notable_cves=("CVE-2018-0101", "CVE-2020-3452", "CVE-2023-20269", "CVE-2024-20353"),
        advisory="https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
        notes=(
            "ASA WebVPN has produced unauthenticated file-read and remote code "
            "execution flaws, and CVE-2023-20269 was abused for credential brute "
            "force against the VPN itself as a ransomware entry point. The 2024 "
            "ArcaneDoor campaign implanted ASA devices directly."
        ),
    ),
    Appliance(
        vendor="SonicWall",
        product="SMA 100/1000 / NetExtender SSL-VPN",
        paths=("/cgi-bin/welcome", "/__api__/v1/logon", "/"),
        body_markers=("sonicwall", "netextender", "virtual office", "/cgi-bin/welcome", "sma 100"),
        cookie_markers=("swap", "sonicwall"),
        location_markers=("/cgi-bin/welcome",),
        version_patterns=(
            re.compile(r"(?:SMA|SonicOS|Firmware)[^0-9]{0,16}(\d+\.\d+\.\d+(?:\.\d+)?(?:-\d+\w*)?)", re.I),
        ),
        notable_cves=("CVE-2021-20016", "CVE-2021-20038", "CVE-2019-7481", "CVE-2024-40766"),
        advisory="https://psirt.global.sonicwall.com/vuln-list",
        notes=(
            "SonicWall SMA appliances have been a recurring ransomware entry point, "
            "including unauthenticated SQL injection and stack overflow flaws "
            "reachable from the VPN portal."
        ),
    ),
    Appliance(
        vendor="Check Point",
        product="Mobile Access / Remote Access VPN",
        paths=("/sslvpn/Login/Login", "/Login/Login", "/"),
        body_markers=("check point", "sslvpn/login", "mobile access portal", "cvpn"),
        location_markers=("/sslvpn/Login/Login",),
        version_patterns=(
            re.compile(r"(?:Check\s*Point|Gaia)[^0-9]{0,16}(R\d+(?:\.\d+)*)", re.I),
        ),
        notable_cves=("CVE-2024-24919",),
        advisory="https://support.checkpoint.com/results/sk/sk182336",
        notes=(
            "CVE-2024-24919 allowed an unauthenticated attacker to read arbitrary "
            "files from a gateway with Remote Access VPN enabled, including the "
            "password hashes of local accounts."
        ),
    ),
)

_MAX_BODY = 200_000


@dataclass(frozen=True)
class _Page:
    """One fetched response, reused across appliance fingerprints in a single call."""

    url: str
    body: str
    headers: dict[str, str]
    cookies: list[str]
    location: str


def _cookie_names(response) -> list[str]:
    values = (
        response.headers.get_list("set-cookie")
        if hasattr(response.headers, "get_list")
        else []
    )
    return [value.split("=", 1)[0].strip().lower() for value in values if value]


def match_appliance(
    appliance: Appliance,
    body: str,
    headers: dict[str, str],
    cookies: list[str],
    location: str,
) -> list[str]:
    """Reasons this response identifies `appliance`. Empty list means no match."""
    reasons: list[str] = []
    lowered_body = body[:_MAX_BODY].lower()
    lowered_headers = {key.lower(): (value or "").lower() for key, value in headers.items()}

    for marker in appliance.body_markers:
        if marker.lower() in lowered_body:
            reasons.append(f"body contains {marker!r}")
    for header, marker in appliance.header_markers:
        if marker.lower() in lowered_headers.get(header, ""):
            reasons.append(f"{header} header contains {marker!r}")
    for marker in appliance.cookie_markers:
        if marker in cookies:
            reasons.append(f"appliance cookie {marker!r} set")
    for marker in appliance.location_markers:
        if marker.lower() in (location or "").lower():
            reasons.append(f"redirects to {marker!r}")
    return reasons


def extract_version(appliance: Appliance, text: str) -> str:
    for pattern in appliance.version_patterns:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return ""


class VpnApplianceExposurePlugin(PluginBase):
    id = "services.vpn_appliance_exposure"
    name = "SSL-VPN / Remote Access Appliance Exposure"
    description = (
        "Fingerprint internet-facing Ivanti, Fortinet, Palo Alto, Cisco ASA, "
        "SonicWall and Check Point remote-access portals and disclose their version"
    )
    category = PluginCategory.services
    severity = Severity.medium
    ports = sorted(VPN_PORTS)

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in _open(host, VPN_PORTS):
            identified = await self._identify(context, host.ip, port)
            if identified is None:
                continue
            appliance, reasons, version, url = identified
            findings.append(
                self._build_finding(host.ip, port, appliance, reasons, version, url)
            )
        return findings

    async def _identify(
        self, context, ip: str, port: int
    ) -> tuple[Appliance, list[str], str, str] | None:
        """Fetch each product's own paths until one response identifies a product.

        Responses are cached per call — never on the instance: the engine runs one
        plugin object against many hosts concurrently, so instance state would
        leak one host's pages into another host's verdict.
        """
        seen: dict[str, _Page] = {}
        for appliance in APPLIANCES:
            for path in appliance.paths:
                page = seen.get(path)
                if page is None:
                    fetched = await self._fetch(context, ip, port, path)
                    if fetched is None:
                        continue
                    url, response = fetched
                    page = _Page(
                        url=url,
                        body=response.text or "",
                        headers=dict(response.headers),
                        cookies=_cookie_names(response),
                        location=response.headers.get("location", ""),
                    )
                    seen[path] = page
                reasons = match_appliance(
                    appliance, page.body, page.headers, page.cookies, page.location
                )
                if reasons:
                    return appliance, reasons, extract_version(appliance, page.body), page.url
        return None

    @staticmethod
    async def _fetch(context, ip: str, port: int, path: str):
        # https only except on plain 80: these appliances do not serve their
        # portal over cleartext, and probing http would just be noise.
        return await _http_get(context, ip, port, path, https=port != 80)

    def _build_finding(
        self,
        ip: str,
        port: int,
        appliance: Appliance,
        reasons: list[str],
        version: str,
        url: str,
    ) -> FindingData:
        # A disclosed version is directly actionable — it lets a reader decide
        # whether a known exploited CVE applies — so it is rated higher than
        # mere identification.
        severity = Severity.medium if version else Severity.low

        version_line = (
            f"Disclosed version: {version}"
            if version
            else "No version string was disclosed by the portal."
        )
        cve_line = (
            "Known exploited vulnerabilities in this product line include "
            + ", ".join(appliance.notable_cves)
            + "."
            if appliance.notable_cves
            else ""
        )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=(
                f"{appliance.vendor} {appliance.product} Exposed"
                + (f" (version {version})" if version else "")
            ),
            description=(
                f"A {appliance.vendor} {appliance.product} remote-access portal is "
                f"reachable at {url or f'{ip}:{port}'}.\n\n"
                "An SSL-VPN portal is an authentication surface that must be reachable "
                "from untrusted networks to do its job, so its exposure is not itself a "
                "misconfiguration. What matters is that this device class has a "
                "sustained history of pre-authentication remote code execution and "
                "authentication bypass, and that the appliance sits at the network "
                "boundary: compromising it yields credentials, session material, and a "
                "position inside the perimeter in one step.\n\n"
                f"{appliance.notes}\n\n"
                f"{version_line} {cve_line}".strip()
            ),
            evidence=(
                f"{url or f'{ip}:{port}'}\n"
                f"Identified as {appliance.vendor} {appliance.product} by:\n"
                + "\n".join(f"  - {reason}" for reason in reasons)
                + (f"\nVersion extracted: {version}" if version else "")
                + "\n\nGET requests only; no credential was submitted."
            ),
            remediation=(
                f"Confirm this appliance is on a supported firmware release and patched "
                f"to the vendor's current recommended build ({appliance.advisory}). "
                "Subscribe to the vendor's PSIRT feed — for this device class the "
                "interval between disclosure and mass exploitation has repeatedly been "
                "measured in days, so a quarterly patch cycle is not fast enough.\n\n"
                "Reduce what is reachable: restrict the management interface to an "
                "internal network (never the same interface as the VPN portal), "
                "geo-fence or allowlist the portal where the user population permits, "
                "and disable portal features that are not in use.\n\n"
                "Require phishing-resistant MFA on the VPN itself. Most incidents in "
                "this device class begin with valid credentials rather than an exploit, "
                "and credentials harvested from an earlier appliance vulnerability stay "
                "valid until they are reset.\n\n"
                "If this device was exposed while a known-exploited vulnerability was "
                "unpatched, patching is not sufficient on its own: run the vendor's "
                "integrity checker, rotate all local and service accounts on the "
                "appliance along with any certificates and API keys it holds, and review "
                "VPN session logs for authentications that do not match a known user."
            ),
            references=[
                appliance.advisory,
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "https://attack.mitre.org/techniques/T1133/",
            ],
            cve_ids=list(appliance.notable_cves),
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"curl -sk -o /dev/null -D - https://{ip}:{port}{appliance.paths[0]}"
            ),
        )
