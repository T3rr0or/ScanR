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

KIBANA_PORTS = [5601, 443, 80]

# Kibana stamps these headers on every response, including its 401s, so they
# identify the product even when authentication is enforced.
KBN_HEADERS = ("kbn-name", "kbn-license-sig", "kbn-version")
# Body markers for the login page. Deliberately narrow: "kibana" on its own
# appears in unrelated documentation and proxy error pages.
LOGIN_MARKERS = ("<title>elastic</title>", "kbn-injected-metadata", "/bundles/app/kibana", "kibanawelcomeview", "<title>kibana</title>")

REFERENCES = [
    "https://www.elastic.co/guide/en/kibana/current/using-kibana-with-security.html",
    "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html",
    "https://attack.mitre.org/techniques/T1213/",
]


def _client(context: "ScanContext") -> httpx.AsyncClient:
    """Single client factory so tests can swap in a MockTransport.

    verify=False: Kibana behind TLS is usually fronted by an internal CA.
    """
    return httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=False, **context.proxy_config())


def _schemes(port: int) -> list[str]:
    if port == 443:
        return ["https"]
    if port == 80:
        return ["http"]
    # 5601 is plaintext in the default distribution but is often TLS-wrapped.
    return ["http", "https"]


async def _fetch(context, ip: str, port: int, path: str, scheme: str | None = None) -> tuple[str, httpx.Response] | None:
    """GET one path. Returns (url, response), or None when nothing answered.

    GET only: /api/status and the saved-object search are both read-only.
    """
    for candidate in [scheme] if scheme else _schemes(port):
        url = f"{candidate}://{ip}:{port}{path}"
        try:
            async with _client(context) as client:
                return url, await client.get(url)
        except Exception:
            continue
    return None


def _status_payload(resp: httpx.Response) -> dict | None:
    """Parse /api/status only if it is genuinely Kibana's status document."""
    try:
        data = json.loads(resp.text[:200000])
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    # Kibana's status document always carries a version block plus either a
    # status summary or the instance name — three keys no generic JSON API
    # produces together.
    version = data.get("version")
    if not isinstance(version, dict) or "number" not in version:
        return None
    if "status" not in data and "name" not in data:
        return None
    return data


class KibanaExposurePlugin(PluginBase):
    id = "services.kibana_exposure"
    name = "Kibana Exposure"
    description = "Detect exposed Kibana instances and unauthenticated access to the Elasticsearch data behind them"
    category = PluginCategory.services
    severity = Severity.high
    ports = KIBANA_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in _open(host, set(KIBANA_PORTS)):
            finding = await self._probe(context, host.ip, port)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, context, ip: str, port: int) -> FindingData | None:
        got = await _fetch(context, ip, port, "/api/status")
        if got is None:
            return None
        url, resp = got
        scheme = url.split(":", 1)[0]
        is_kibana = any(h in resp.headers for h in KBN_HEADERS)

        payload = _status_payload(resp) if resp.status_code == 200 else None
        if payload:
            return await self._unauthenticated_finding(context, ip, port, scheme, url, payload)

        # 401/403 with Kibana's own headers: product present, auth enforced.
        if is_kibana or resp.status_code in (401, 403):
            confirmed = is_kibana
            evidence = [f"GET {url} -> HTTP {resp.status_code}"]
            if is_kibana:
                header = next(h for h in KBN_HEADERS if h in resp.headers)
                evidence.append(f"{header}: {resp.headers[header]}")
            if not confirmed:
                # Fall back to the login page before claiming this is Kibana —
                # a bare 401 is produced by any password-protected web server.
                login = await _fetch(context, ip, port, "/login", scheme=scheme)
                if login and any(m in login[1].text[:20000].lower() for m in LOGIN_MARKERS):
                    confirmed = True
                    evidence.append(f"GET {login[0]} -> Kibana login page")
            if not confirmed:
                return None
            return FindingData(
                plugin_id=self.id,
                severity=Severity.low,
                title="Kibana Detected — Authentication Enforced",
                description=(
                    f"A Kibana instance is reachable on port {port} but rejects unauthenticated requests to "
                    "/api/status. No index data is exposed. The instance still identifies an Elasticsearch cluster "
                    "on this network to an attacker, making it a target for credential stuffing and for any "
                    "authentication-bypass advisory affecting the installed release."
                ),
                evidence="; ".join(evidence),
                remediation=(
                    "Keep the Elastic Stack security features enabled, put Kibana behind SSO/MFA, and restrict "
                    "network access to the analysts who need it."
                ),
                references=REFERENCES,
                port_number=port,
                protocol="tcp",
            )
        return None

    async def _unauthenticated_finding(self, context, ip: str, port: int, scheme: str, url: str, payload: dict) -> FindingData:
        version = str(payload.get("version", {}).get("number", "unknown"))
        instance = str(payload.get("name", ""))
        evidence = [f"GET {url} -> HTTP 200, Kibana {version}" + (f" (instance '{instance}')" if instance else "")]

        # /api/status can be deliberately whitelisted for load balancers, so
        # prove the data plane is open before calling this critical: reading
        # saved objects means the Elasticsearch behind Kibana answers too.
        data_plane = await self._probe_saved_objects(context, ip, port, scheme)
        if data_plane:
            evidence.append(f"GET {data_plane} -> HTTP 200 listing Kibana saved objects (index patterns)")
            return FindingData(
                plugin_id=self.id,
                severity=Severity.critical,
                title=f"Kibana {version} — Unauthenticated Access to Elasticsearch Data",
                description=(
                    f"Kibana on port {port} answered an unauthenticated saved-object query, returning the index "
                    "patterns configured on the instance. Kibana stores no data itself: it proxies searches to "
                    "Elasticsearch using its own configured credentials, so an attacker who can query Kibana can "
                    "read every index it is wired to — application logs, customer records, and any secrets that "
                    "ended up in log lines — and can create or modify saved searches and dashboards. The exposed "
                    f"version ({version}) additionally lets them match this instance against published Elastic "
                    "advisories."
                ),
                evidence="; ".join(evidence),
                remediation=(
                    "Enable the Elastic Stack security features (xpack.security.enabled: true) on Elasticsearch "
                    "and Kibana, require an authenticated session for every route, and front the instance with "
                    "SSO/MFA. Bind both services to internal interfaces, then audit which indices were readable "
                    "and rotate any credentials or tokens that appear in them."
                ),
                references=REFERENCES,
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                port_number=port,
                protocol="tcp",
            )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title=f"Kibana {version} Exposed Without Authentication",
            description=(
                f"Kibana on port {port} serves /api/status to unauthenticated clients, disclosing its exact "
                f"version ({version}) and instance name. More importantly, Kibana holds no data of its own: it is "
                "a front end for an Elasticsearch cluster, and it queries that cluster with its own configured "
                "credentials. An unauthenticated Kibana therefore almost always means every index behind it — "
                "application logs, customer records, API keys and tokens captured in log lines — can be read "
                "through the Kibana UI and its search APIs, and dashboards or saved objects can be altered. The "
                "version string additionally lets an attacker match the instance against published Elastic "
                "security advisories."
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Enable the Elastic Stack security features (xpack.security.enabled: true) on both Elasticsearch "
                "and Kibana, require authenticated sessions for every Kibana route, and place the instance behind "
                "SSO/MFA. Bind Kibana and Elasticsearch to internal interfaces only, and audit the indices that "
                "were readable while it was open."
            ),
            references=REFERENCES,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            port_number=port,
            protocol="tcp",
        )

    @staticmethod
    async def _probe_saved_objects(context, ip: str, port: int, scheme: str) -> str | None:
        """Read-only check that the data plane, not just /api/status, is open."""
        got = await _fetch(context, ip, port, "/api/saved_objects/_find?type=index-pattern&per_page=1", scheme=scheme)
        if got and got[1].status_code == 200 and "saved_objects" in got[1].text[:4000]:
            return got[0]
        return None
