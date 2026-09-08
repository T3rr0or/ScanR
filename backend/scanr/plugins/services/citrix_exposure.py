from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.services._pentest_common import _open

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

CITRIX_PORTS = [443, 80]

# Body markers unique to the NetScaler/ADC/Gateway appliance stack. Generic
# words like "citrix" alone are avoided — plenty of unrelated pages mention it.
GATEWAY_MARKERS = (
    "/vpn/js/rdx/",
    "citrix gateway",
    "netscaler gateway",
    "citrix access gateway",
    "logonpoint",
    "_ctxstxxxx",
    "ns_af",
)
# The management GUI (NSIP) is a different, far more sensitive surface than the
# gateway VIP: it is the appliance's configuration plane.
MGMT_MARKERS = ("neo/main.html", "nsgui", "ns_gui", "configuration utility", "netscaler console")

# NSC_ cookies are set by the appliance itself and are the strongest signal.
_NSC_COOKIE_RE = re.compile(r"\bNSC_[A-Z0-9_]+\s*=", re.I)
# Version leaks: build query strings on gateway assets and the vpn config JSON.
_VERSION_RES = (
    re.compile(r"(?:NetScaler|Citrix\s+ADC|Citrix\s+Gateway)[^0-9]{0,16}(1?[0-9]{1,2}\.[0-9]+(?:[.\-][0-9]+){0,3})", re.I),
    re.compile(r"nsversion[\"'\s:=]+([0-9]{1,2}\.[0-9]+(?:[.\-][0-9]+){0,3})", re.I),
    re.compile(r"/vpn/js/[^\"'\s]*[?&]v(?:ersion)?=([0-9]{1,2}\.[0-9]+(?:[.\-][0-9]+){0,3})", re.I),
)

REFERENCES = [
    "https://support.citrix.com/securitybulletins",
    "https://attack.mitre.org/techniques/T1133/",
]


def _client(context: "ScanContext") -> httpx.AsyncClient:
    """Single client factory so tests can swap in a MockTransport.

    verify=False: appliances are routinely fronted by an expired or internal-CA
    certificate, and a TLS error would hide the appliance entirely.
    """
    return httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=False, **context.proxy_config())


def _schemes(port: int) -> list[str]:
    return ["http"] if port == 80 else ["https"]


async def _fetch(context, ip: str, port: int, path: str, scheme: str | None = None) -> tuple[str, httpx.Response] | None:
    """GET one path. Returns (url, response), or None when nothing answered.

    GET only — this plugin never posts to the logon endpoints it fingerprints.
    """
    for candidate in [scheme] if scheme else _schemes(port):
        url = f"{candidate}://{ip}:{port}{path}"
        try:
            async with _client(context) as client:
                return url, await client.get(url)
        except Exception:
            continue
    return None


def _extract_version(text: str) -> str:
    for pattern in _VERSION_RES:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return ""


class CitrixExposurePlugin(PluginBase):
    id = "services.citrix_exposure"
    name = "Citrix ADC / NetScaler Gateway Exposure"
    description = "Detect exposed Citrix ADC, NetScaler, or Gateway endpoints and version disclosure"
    category = PluginCategory.services
    severity = Severity.medium
    ports = CITRIX_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in _open(host, set(CITRIX_PORTS)):
            finding = await self._probe(context, host.ip, port)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, context, ip: str, port: int) -> FindingData | None:
        evidence: list[str] = []
        confirmed = False
        version = ""
        scheme: str | None = None

        for path in ("/vpn/index.html", "/logon/LogonPoint/index.html", "/"):
            got = await _fetch(context, ip, port, path, scheme=scheme)
            if got is None:
                continue
            url, resp = got
            scheme = url.split(":", 1)[0]
            body = resp.text[:20000]
            lowered = body.lower()

            # Set-Cookie: NSC_* is emitted by the appliance on almost every
            # response and is not something a generic web server produces.
            cookie_header = ", ".join(resp.headers.get_list("set-cookie"))
            if _NSC_COOKIE_RE.search(cookie_header):
                confirmed = True
                evidence.append(f"{url} set NSC_ appliance cookie")

            hit = next((m for m in GATEWAY_MARKERS if m in lowered), "")
            if hit:
                confirmed = True
                evidence.append(f"GET {url} -> HTTP {resp.status_code}, matched '{hit}'")

            if confirmed and not version:
                version = _extract_version(body)
            if confirmed:
                break

        if not confirmed:
            return None

        if version:
            evidence.append(f"version disclosed: {version}")

        # The configuration utility answering on the same VIP is the finding
        # that matters: that plane configures the appliance and has repeatedly
        # been the entry point for pre-authentication appliance takeover.
        mgmt = await _fetch(context, ip, port, "/menu/neo", scheme=scheme)
        if mgmt and mgmt[1].status_code in (200, 302) and self._is_mgmt(mgmt[1]):
            return FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title="Citrix ADC / NetScaler Management Interface Reachable",
                description=(
                    f"The NetScaler configuration utility (management plane) answered on port {port}. This "
                    "interface configures the appliance itself: load-balancing rules, TLS private keys, LDAP/AD "
                    "bind credentials stored for gateway authentication, and the responder policies that can be "
                    "used to run code on the appliance. It is meant to be reachable only from a dedicated NSIP "
                    "management network, and the pre-authentication vulnerabilities Citrix has published over the "
                    "years have almost all been reachable through exactly these management and gateway paths."
                ),
                evidence="; ".join(evidence + [f"GET {mgmt[0]} -> HTTP {mgmt[1].status_code} (configuration utility)"]),
                remediation=(
                    "Bind the management interface (NSIP) to a management-only VLAN and block it on every public "
                    "VIP. Restrict access with `set ns ip -gui SECUREONLY` and management ACLs, enforce MFA for "
                    "administrators, and apply the current Citrix security bulletins for the installed build."
                ),
                references=REFERENCES,
                cvss_score=8.6,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                port_number=port,
                protocol="tcp",
            )

        if version:
            return FindingData(
                plugin_id=self.id,
                severity=Severity.medium,
                title=f"Citrix ADC / Gateway Exposed — Version {version} Disclosed",
                description=(
                    f"A Citrix ADC/NetScaler Gateway is reachable on port {port} and leaks its firmware version "
                    "before authentication. The gateway terminates remote-access sessions for the whole "
                    "organisation, so an attacker who reads the build simply checks it against Citrix's published "
                    "bulletins: unpatched builds in this product line have yielded pre-auth session-token theft "
                    "and remote code execution on the appliance, which is a foothold inside the network perimeter "
                    "with the gateway's stored AD credentials attached."
                ),
                evidence="; ".join(evidence),
                remediation=(
                    f"Upgrade to a current, supported firmware build (running {version}) and confirm the vendor "
                    "mitigations for any bulletin affecting it. Suppress version strings from logon page assets, "
                    "enforce MFA on the gateway, and keep the management plane off public VIPs."
                ),
                references=REFERENCES,
                port_number=port,
                protocol="tcp",
            )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.low,
            title="Citrix ADC / Gateway Logon Endpoint Detected",
            description=(
                f"A Citrix ADC/NetScaler Gateway logon endpoint was fingerprinted on port {port}. Authentication "
                "is enforced and no version string was disclosed. This is expected for an internet-facing remote "
                "access gateway, but it identifies the appliance to an attacker as a credential-stuffing and "
                "pre-auth exploitation target that fronts the internal network."
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Enforce MFA on gateway authentication, keep firmware current with Citrix security bulletins, and "
                "ensure only the gateway VIP — never the management interface — is publicly reachable."
            ),
            references=REFERENCES,
            port_number=port,
            protocol="tcp",
        )

    @staticmethod
    def _is_mgmt(resp: httpx.Response) -> bool:
        lowered = resp.text[:8000].lower()
        location = resp.headers.get("location", "").lower()
        return any(m in lowered for m in MGMT_MARKERS) or any(m in location for m in MGMT_MARKERS)
