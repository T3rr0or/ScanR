from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.services._pentest_common import _open, _tcp_probe

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

ESXI_PORTS = [443, 80, 902]
HTTP_PORTS = {443, 80}
AUTHD_PORT = 902

# The vSphere SOAP endpoint always advertises the vim25 namespace; nothing else
# on the internet serves that string, which is what keeps this fingerprint from
# matching arbitrary web servers.
SDK_MARKERS = ("urn:vim25", "urn:vim2", "vimservice")
# Welcome page / host client markers. "id_eesx_welcome" is the untranslated
# title key ESXi ships when no locale bundle matched — a very strong tell.
UI_MARKERS = ("vmware esxi", "id_eesx_welcome", "vsphere client", "vmware vcenter", "esxi host client")

# /client/clients.xml is served pre-auth and carries the exact product version.
_XML_VERSION_RE = re.compile(r"<version>\s*([0-9]+(?:\.[0-9]+){1,3})\s*</version>", re.I)
# Build numbers appear in the welcome page footer and in authd's banner.
_BUILD_RE = re.compile(r"build[\s\-_:]*([0-9]{5,9})", re.I)
# authd greets with e.g. "220 VMware Authentication Daemon Version 1.10: SSL Required"
_AUTHD_RE = re.compile(r"VMware Authentication Daemon Version ([0-9.]+)", re.I)

REFERENCES = [
    "https://www.vmware.com/security/advisories.html",
    "https://attack.mitre.org/techniques/T1133/",
]


def _client(context: "ScanContext") -> httpx.AsyncClient:
    """Single client factory so tests can swap in a MockTransport.

    verify=False because ESXi ships a self-signed certificate by default —
    validating would silently drop exactly the hosts worth reporting.
    """
    return httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=False, **context.proxy_config())


def _schemes(port: int) -> list[str]:
    return ["http"] if port == 80 else ["https"]


async def _fetch(context, ip: str, port: int, path: str, scheme: str | None = None) -> tuple[str, httpx.Response] | None:
    """GET one path. Returns (url, response), or None when nothing answered.

    Read-only by contract: this plugin only ever issues GET and never supplies
    credentials.
    """
    for candidate in [scheme] if scheme else _schemes(port):
        url = f"{candidate}://{ip}:{port}{path}"
        try:
            async with _client(context) as client:
                return url, await client.get(url)
        except Exception:
            continue
    return None


class EsxiExposurePlugin(PluginBase):
    id = "services.esxi_exposure"
    name = "VMware ESXi / vCenter Exposure"
    description = "Detect exposed VMware ESXi or vCenter management interfaces and version disclosure"
    category = PluginCategory.services
    severity = Severity.medium
    ports = ESXI_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in _open(host, set(ESXI_PORTS)):
            if port == AUTHD_PORT:
                finding = await self._probe_authd(host.ip, port)
            else:
                finding = await self._probe_http(context, host.ip, port)
            if finding:
                findings.append(finding)
        return findings

    async def _probe_http(self, context, ip: str, port: int) -> FindingData | None:
        # The SOAP endpoint is the cheapest unambiguous fingerprint, and it is
        # also the pre-auth attack surface that matters (the ESXiArgs wave and
        # every "unauthenticated vCenter" advisory landed here, not on /ui/).
        got = await _fetch(context, ip, port, "/sdk/vimServiceVersions.xml")
        if got is None:
            return None
        scheme = got[0].split(":", 1)[0]

        evidence: list[str] = []
        product = "VMware vSphere"
        confirmed = False
        api_versions: list[str] = []

        url, resp = got
        body = resp.text[:20000]
        if resp.status_code == 200 and any(m in body.lower() for m in SDK_MARKERS):
            confirmed = True
            api_versions = _XML_VERSION_RE.findall(body)
            evidence.append(f"GET {url} -> HTTP 200, vim25 SOAP namespace advertised")
            if api_versions:
                evidence.append("advertised vSphere API versions: " + ", ".join(sorted(set(api_versions))[:6]))

        # Welcome page / host client tells ESXi apart from vCenter and often
        # carries the build number in the footer.
        root = await _fetch(context, ip, port, "/", scheme=scheme)
        version = ""
        build = ""
        if root:
            rurl, rresp = root
            rbody = rresp.text[:20000]
            lowered = rbody.lower()
            server = rresp.headers.get("server", "")
            hit = next((m for m in UI_MARKERS if m in lowered), "")
            if hit or "vmware" in server.lower():
                confirmed = True
                product = "VMware vCenter Server" if ("vcenter" in lowered or "vsphere client" in lowered) else "VMware ESXi"
                evidence.append(f"GET {rurl} -> HTTP {rresp.status_code}, matched {hit or 'Server: ' + server}")
            if hit or confirmed:
                found_build = _BUILD_RE.search(rbody)
                if found_build:
                    build = found_build.group(1)

        if not confirmed:
            return None

        # clients.xml is unauthenticated on every shipping release and states the
        # exact product version, which maps one-to-one onto published advisories.
        clients = await _fetch(context, ip, port, "/client/clients.xml", scheme=scheme)
        if clients and clients[1].status_code == 200:
            cbody = clients[1].text[:8000]
            match = _XML_VERSION_RE.search(cbody)
            if match and "<clientconnection" in cbody.lower():
                version = match.group(1)
                evidence.append(f"GET {clients[0]} -> HTTP 200 disclosing version {version}")
                if not build:
                    found_build = _BUILD_RE.search(cbody)
                    if found_build:
                        build = found_build.group(1)

        # /folder is the datastore browser. It demands a session on a healthy
        # host; a 200 here means VM disks and ISOs are listable by anyone.
        folder = await _fetch(context, ip, port, "/folder", scheme=scheme)
        if folder and folder[1].status_code == 200 and self._is_datastore_listing(folder[1].text):
            return FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title=f"{product} — Datastore Browser Readable Without Authentication",
                description=(
                    f"The vSphere datastore browser on port {port} returned a directory listing without a session "
                    "cookie. An attacker can enumerate and download virtual machine disks (.vmdk), NVRAM, and "
                    "configuration files straight off the datastore — that is offline access to every guest OS on "
                    "the host, including their credential stores, with no hypervisor login required."
                ),
                evidence="; ".join(evidence + [f"GET {folder[0]} -> HTTP 200 with datastore directory listing"]),
                remediation=(
                    "Restrict the management interface to a dedicated management VLAN, verify no reverse proxy in "
                    "front of the host strips or injects vSphere session headers, and confirm /folder requires a "
                    "valid session. Rotate any credentials stored inside guests that were exposed."
                ),
                references=REFERENCES,
                cvss_score=8.6,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                port_number=port,
                protocol="tcp",
            )

        release = " ".join(part for part in [version, f"build {build}" if build else ""] if part).strip()
        if release:
            return FindingData(
                plugin_id=self.id,
                severity=Severity.medium,
                title=f"{product} Management Interface Exposed — Version {release} Disclosed",
                description=(
                    f"{product} is reachable on port {port} and discloses its exact version pre-authentication. "
                    "ESXi and vCenter builds map directly onto published VMware advisories, so an attacker reads "
                    "the version, looks up the unpatched pre-auth flaws for that build, and knows before touching "
                    "the host whether it is exploitable. Hypervisor compromise means every guest VM on the host is "
                    "compromised, which is how the ESXi ransomware campaigns operated."
                ),
                evidence="; ".join(evidence),
                remediation=(
                    "Do not expose the vSphere management interface to untrusted networks — bind it to a management "
                    "VLAN reachable only over VPN or a jump host. Apply the current VMware security advisories for "
                    f"{release}, disable unused services (SLP, CIM), and enable ESXi lockdown mode."
                ),
                references=REFERENCES,
                port_number=port,
                protocol="tcp",
            )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.low,
            title=f"{product} Management Interface Detected",
            description=(
                f"{product} was fingerprinted on port {port}. Authentication is enforced on the endpoints probed, "
                "but the presence of a hypervisor management interface on this network path is itself useful to an "
                "attacker: it identifies a high-value target whose compromise yields every guest VM, and the SOAP "
                "endpoint has repeatedly carried pre-authentication vulnerabilities."
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Restrict the management interface to a dedicated management network, enable lockdown mode, and "
                "subscribe to VMware security advisories so pre-auth SOAP flaws are patched on release."
            ),
            references=REFERENCES,
            port_number=port,
            protocol="tcp",
        )

    @staticmethod
    def _is_datastore_listing(text: str) -> bool:
        lowered = text[:8000].lower()
        # Require vSphere-specific listing markers so a generic /folder page on
        # an unrelated app behind the same IP cannot trigger a high finding.
        return "directory listing of" in lowered or "dspath" in lowered or "dcpath" in lowered

    async def _probe_authd(self, ip: str, port: int) -> FindingData | None:
        """Port 902 speaks a plaintext greeting, not HTTP — grab the banner."""
        try:
            banner = (await _tcp_probe(ip, port, read=256)).decode("utf-8", "replace")
        except Exception:
            return None
        match = _AUTHD_RE.search(banner)
        if not match:
            return None
        return FindingData(
            plugin_id=self.id,
            severity=Severity.low,
            title="VMware Authentication Daemon (authd) Reachable",
            description=(
                f"The VMware authentication daemon is answering on port {port} and announces itself in its banner. "
                "authd brokers console (VMRC) and datastore access to guest VMs, so its reachability tells an "
                "attacker a hypervisor lives here and gives them a credential-guessing surface separate from the "
                "web UI, where login attempts are less likely to be watched."
            ),
            evidence=f"tcp/{port} banner: {banner.strip()[:200]} (authd version {match.group(1)})",
            remediation=(
                "Restrict port 902 to the management VLAN and to the vCenter server that needs it. Console access "
                "should reach the host through vCenter, not directly from user networks."
            ),
            references=REFERENCES,
            port_number=port,
            protocol="tcp",
        )
