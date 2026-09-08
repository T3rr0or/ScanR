"""Portainer exposure and unclaimed-instance detection.

Portainer is a web UI in front of a Docker or Kubernetes socket, so whoever
controls it controls the host: it can start a container with the host filesystem
bind-mounted, which is root on the machine. Two things are worth reporting about
one that is reachable.

The severe one is an *unclaimed* instance. On first run Portainer has no admin
account, and ``GET /api/users/admin/check`` answers 404 to say so. In that state
the account-creation endpoint is open to whoever reaches it first, so an attacker
who finds the instance before its operator finishes the install owns the Docker
host behind it. (Portainer 1.23+ closes the initial-setup window a few minutes
after startup, so exploitation may need to coincide with a restart — but
restarts happen on every upgrade and reboot, and an attacker who has found the
instance can simply wait for one.)

The milder one is version disclosure plus a login page on the perimeter, which
is a credential-stuffing target and lets an attacker match the build against
published Portainer advisories.

Everything here is a GET of a documented status endpoint. This plugin never
posts to /api/users/admin/init, never submits credentials, and never touches the
Docker API it fronts.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.services._pentest_common import _open

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

PORTAINER_PORTS = [9000, 9443]

# /api/status is the classic endpoint; 2.18 moved it under /api/system and keeps
# the old path as a deprecated alias, so both are tried.
STATUS_PATHS = ("/api/status", "/api/system/status")
ADMIN_CHECK_PATH = "/api/users/admin/check"

# Keys that only Portainer's status document carries. "Version" on its own is
# far too common to fingerprint on — a generic /api/status returning
# {"Version": "1.0"} must never be mistaken for Portainer, because the admin
# check below reads a 404 as "this instance is unclaimed".
_STATUS_MARKERS = {
    "instanceid",
    "demoenvironment",
    "endpointmanagement",
    "authentication",
    "edition",
    "serveredition",
}

REFERENCES = [
    "https://docs.portainer.io/",
    "https://docs.docker.com/engine/security/",
    "https://cwe.mitre.org/data/definitions/306.html",
    "https://attack.mitre.org/techniques/T1610/",
]


def _client(context: "ScanContext") -> httpx.AsyncClient:
    """Single client factory so tests can swap in a MockTransport."""
    return httpx.AsyncClient(
        verify=False, timeout=6.0, follow_redirects=False, **context.proxy_config()
    )


def _schemes(port: int) -> list[str]:
    # 9443 is Portainer's built-in HTTPS listener; 9000 is plaintext, but is
    # often TLS-terminated in place by a reverse proxy.
    return ["https"] if port == 9443 else ["http", "https"]


async def _fetch(
    context, ip: str, port: int, path: str, scheme: str | None = None
) -> tuple[str, httpx.Response] | None:
    """GET one path. Returns (url, response), or None when nothing answered."""
    for candidate in [scheme] if scheme else _schemes(port):
        url = f"{candidate}://{ip}:{port}{path}"
        try:
            async with _client(context) as client:
                return url, await client.get(url)
        except Exception:
            continue
    return None


def _json_dict(resp: httpx.Response) -> dict | None:
    try:
        data = json.loads(resp.text[:200000])
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _is_portainer_status(data: dict | None) -> bool:
    """True only for a document that is recognisably Portainer's own status."""
    if not data:
        return False
    keys = {str(key).lower() for key in data}
    return "version" in keys and bool(keys & _STATUS_MARKERS)


def _version_of(data: dict | None) -> str:
    if not data:
        return ""
    for key, value in data.items():
        if str(key).lower() == "version" and isinstance(value, str):
            return value.strip()[:32]
    return ""


class PortainerExposurePlugin(PluginBase):
    id = "services.portainer_exposure"
    name = "Portainer Exposure"
    description = "Detect exposed Portainer instances, including unclaimed instances with no admin account"
    category = PluginCategory.services
    severity = Severity.critical
    ports = PORTAINER_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in _open(host, set(PORTAINER_PORTS)):
            try:
                finding = await self._probe(context, host.ip, port)
            except Exception:
                logger.debug(
                    "portainer_exposure: probe failed for %s:%d", host.ip, port, exc_info=True
                )
                continue
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, context, ip: str, port: int) -> FindingData | None:
        fingerprint = await self._fingerprint(context, ip, port)
        if fingerprint is None:
            return None
        url, scheme, data = fingerprint

        version = _version_of(data)
        label = f"Portainer {version}" if version else "Portainer"
        evidence = [f"GET {url} -> HTTP 200 Portainer status (version={version or 'not disclosed'})"]

        admin = await _fetch(context, ip, port, ADMIN_CHECK_PATH, scheme=scheme)
        if admin is None:
            return self._exposure_finding(port, label, version, evidence, admin_known=False)
        admin_url, admin_resp = admin
        evidence.append(f"GET {admin_url} -> HTTP {admin_resp.status_code}")

        if admin_resp.status_code == 404 and not self._looks_like_error_page(admin_resp):
            return self._unclaimed_finding(port, label, version, evidence)
        if admin_resp.status_code in (200, 204):
            return self._exposure_finding(port, label, version, evidence, admin_known=True)
        return self._exposure_finding(port, label, version, evidence, admin_known=False)

    async def _fingerprint(
        self, context, ip: str, port: int
    ) -> tuple[str, str, dict] | None:
        """Confirm Portainer from its status document before anything else runs."""
        scheme: str | None = None
        for path in STATUS_PATHS:
            got = await _fetch(context, ip, port, path, scheme=scheme)
            if got is None:
                continue
            url, resp = got
            # Remember which scheme answered so the follow-up GETs do not retry
            # the other one against a service that has already replied.
            scheme = url.split(":", 1)[0]
            if resp.status_code != 200:
                continue
            data = _json_dict(resp)
            if data is not None and _is_portainer_status(data):
                return url, scheme, data
        return None

    @staticmethod
    def _looks_like_error_page(resp: httpx.Response) -> bool:
        """A reverse proxy's HTML 404 in front of the API is not Portainer saying
        'no admin exists'. Portainer answers this endpoint with JSON."""
        body = resp.text[:2000].lstrip().lower()
        return body.startswith("<!doctype") or body.startswith("<html")

    def _unclaimed_finding(
        self, port: int, label: str, version: str, evidence: list[str]
    ) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title=f"{label} Instance Is Unclaimed — No Admin Account Created",
            description=(
                f"The Portainer instance on port {port} reports that no administrator account "
                "exists yet: GET /api/users/admin/check returned 404, which is how Portainer "
                "signals that it is still in initial-setup state. Anyone who can reach this "
                "port can therefore create the first administrator account and take ownership "
                "of the instance. That is not merely access to a dashboard — Portainer is a "
                "front end to the Docker or Kubernetes API, so its administrator can start a "
                "privileged container with the host filesystem mounted and read or write any "
                "file on the host as root, dump the environment variables and secrets of every "
                "running container, and pivot into every network those containers are attached "
                "to. Portainer 1.23 and later close the setup window a few minutes after "
                "startup, so an attacker may have to catch the instance shortly after a restart "
                "— an upgrade, a reboot, or a crash-loop is enough, and an attacker who has "
                "already found the instance can wait for one."
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Create the administrator account immediately, from a trusted network, and "
                "verify in the user list that no unexpected account already exists — if one "
                "does, treat the Docker host and every container on it as compromised. "
                "Then remove the instance from the perimeter: bind it to localhost or an "
                "internal interface, put it behind a VPN or authenticating reverse proxy, and "
                "firewall 9000/9443. "
                "Provision the admin password at deploy time with --admin-password-file so a "
                "new instance is never unclaimed, and enable MFA once an admin exists."
            ),
            references=REFERENCES,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            port_number=port,
            protocol="tcp",
        )

    def _exposure_finding(
        self, port: int, label: str, version: str, evidence: list[str], *, admin_known: bool
    ) -> FindingData:
        state = (
            "An administrator account already exists, so the instance cannot be claimed."
            if admin_known
            else "The instance's setup state could not be determined."
        )
        return FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title=f"{label} Management Interface Exposed",
            description=(
                f"A Portainer management interface is reachable on port {port}. {state} Exposure "
                "still matters: Portainer administers the Docker or Kubernetes API, so a single "
                "valid credential is equivalent to root on the container host — an authenticated "
                "user can run a privileged container that mounts the host filesystem. A "
                "reachable login page is therefore a credential-stuffing and brute-force target "
                "whose payoff is the whole host"
                + (
                    f", and the disclosed version ({version}) lets an attacker match this build "
                    "against published Portainer advisories rather than probing for them."
                    if version
                    else "."
                )
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Do not expose Portainer to untrusted networks: bind it to an internal interface "
                "or place it behind a VPN or an authenticating reverse proxy, and firewall "
                "9000/9443. Serve it over HTTPS only, enable MFA, and use the least-privileged "
                "role for day-to-day users rather than shared administrator accounts. "
                "Keep the instance on a supported release, and restrict which environments "
                "(Docker endpoints) each user can reach."
            ),
            references=REFERENCES,
            port_number=port,
            protocol="tcp",
        )
