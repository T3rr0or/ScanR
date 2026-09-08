from __future__ import annotations

import json
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

AIRFLOW_PORTS = [8080, 8081, 443]

# Login page markers. Airflow's Flask-AppBuilder UI serves its own static
# bundle, so these paths do not appear on unrelated web servers.
LOGIN_MARKERS = (
    "/static/appbuilder/",
    "airflow-main-content",
    "<title>sign in - airflow</title>",
    "apache airflow",
    "airflow.apache.org",
)
_VERSION_RES = (
    re.compile(r"airflow[^0-9a-z]{0,12}v?([0-9]+\.[0-9]+\.[0-9]+)", re.I),
    re.compile(r"/static/appbuilder/[^\"'\s]*[?&]ver(?:sion)?=([0-9]+\.[0-9]+\.[0-9]+)", re.I),
)

REFERENCES = [
    "https://airflow.apache.org/docs/apache-airflow/stable/security/index.html",
    "https://airflow.apache.org/docs/apache-airflow/stable/security/api.html",
    "https://attack.mitre.org/techniques/T1552/007/",
]


def _client(context: "ScanContext") -> httpx.AsyncClient:
    """Single client factory so tests can swap in a MockTransport."""
    return httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=False, **context.proxy_config())


def _schemes(port: int) -> list[str]:
    if port == 443:
        return ["https"]
    # The webserver is plaintext by default but is often TLS-terminated in place.
    return ["http", "https"]


async def _fetch(context, ip: str, port: int, path: str, scheme: str | None = None) -> tuple[str, httpx.Response] | None:
    """GET one path. Returns (url, response), or None when nothing answered.

    GET only. Listing DAGs and connections is read-only; this plugin never
    triggers a DAG run and never posts to /api/v1.
    """
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


def _is_airflow_health(data: dict | None) -> bool:
    """Airflow's /health names its own components — a generic {"status":"ok"}
    health endpoint must not be mistaken for it."""
    if not data:
        return False
    return "metadatabase" in data and ("scheduler" in data or "triggerer" in data or "dag_processor" in data)


class AirflowExposurePlugin(PluginBase):
    id = "services.airflow_exposure"
    name = "Apache Airflow Exposure"
    description = "Detect exposed Apache Airflow webservers and unauthenticated DAG or connection access"
    category = PluginCategory.services
    severity = Severity.high
    ports = AIRFLOW_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in _open(host, set(AIRFLOW_PORTS)):
            finding = await self._probe(context, host.ip, port)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, context, ip: str, port: int) -> FindingData | None:
        got = await _fetch(context, ip, port, "/health")
        if got is None:
            return None
        url, resp = got
        scheme = url.split(":", 1)[0]

        evidence: list[str] = []
        confirmed = False
        version = ""

        health = _json_dict(resp) if resp.status_code == 200 else None
        if _is_airflow_health(health):
            confirmed = True
            components = ", ".join(f"{k}={v.get('status')}" for k, v in health.items() if isinstance(v, dict))
            evidence.append(f"GET {url} -> HTTP 200 Airflow health ({components})")

        # The login page confirms the product when /health is blocked and is
        # where the version string is usually rendered.
        login = await _fetch(context, ip, port, "/login/", scheme=scheme)
        if login:
            body = login[1].text[:20000]
            hit = next((m for m in LOGIN_MARKERS if m in body.lower()), "")
            if hit:
                confirmed = True
                evidence.append(f"GET {login[0]} -> HTTP {login[1].status_code}, matched '{hit}'")
            if hit or confirmed:
                for pattern in _VERSION_RES:
                    match = pattern.search(body)
                    if match:
                        version = match.group(1)
                        break

        if not confirmed:
            return None
        label = f"Airflow {version}" if version else "Airflow"

        # Connections are the worst case: the API returns the connection
        # inventory Airflow uses to reach every system it orchestrates.
        conns = await _fetch(context, ip, port, "/api/v1/connections?limit=1", scheme=scheme)
        if conns and conns[1].status_code == 200:
            data = _json_dict(conns[1])
            if data is not None and "connections" in data:
                evidence.append(f"GET {conns[0]} -> HTTP 200 listing connections (total_entries={data.get('total_entries')})")
                return self._critical(
                    port,
                    f"Apache {label} — Unauthenticated Access to Orchestration Connections",
                    (
                        f"The Airflow REST API on port {port} returned the connection inventory without "
                        "authentication. Connections are Airflow's credential store: database DSNs, cloud "
                        "provider accounts, SSH hosts, and API tokens for every system it orchestrates. Reading "
                        "them hands an attacker the keys to the surrounding estate, and the same unauthenticated "
                        "API also accepts DAG triggers and variable writes — which execute attacker-influenced "
                        "code on the Airflow workers."
                    ),
                    evidence,
                )

        # DAG listing is the more common finding and is nearly as bad: the same
        # unauthenticated API that lists DAGs also accepts POST dagRuns.
        dags = await _fetch(context, ip, port, "/api/v1/dags?limit=1", scheme=scheme)
        if dags and dags[1].status_code == 200:
            data = _json_dict(dags[1])
            if data is not None and "dags" in data:
                evidence.append(f"GET {dags[0]} -> HTTP 200 listing DAGs (total_entries={data.get('total_entries')})")
                return self._critical(
                    port,
                    f"Apache {label} — Unauthenticated DAG Listing via REST API",
                    (
                        f"The Airflow REST API on port {port} listed DAGs without authentication, which means the "
                        "API's auth backend allows anonymous access. The same API exposes /api/v1/connections and "
                        "/api/v1/variables — Airflow's credential store for every database, cloud account, and "
                        "SSH host it orchestrates — and accepts DAG-run triggers, so an attacker can execute the "
                        "pipelines' code paths on the workers. DAG names alone also map out the organisation's "
                        "data flows and internal system names."
                    ),
                    evidence,
                )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.medium if version else Severity.low,
            title=f"Apache {label} Webserver Detected — Authentication Enforced",
            description=(
                f"An Apache Airflow webserver is reachable on port {port}, but the REST API rejected "
                "unauthenticated requests to /api/v1/dags. No DAGs or connections were readable. Exposure still "
                "matters: Airflow holds credentials for everything it orchestrates, so its login page is a "
                "high-value credential-stuffing target"
                + (f", and the disclosed version ({version}) lets an attacker check it against published Airflow "
                   "advisories." if version else ".")
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Keep the API auth backend set to a real authenticator (never api.auth_backend = "
                "airflow.api.auth.backend.default on a reachable interface), require SSO/MFA for the web UI, "
                "restrict the webserver to trusted networks, and keep the deployment on a supported release."
            ),
            references=REFERENCES,
            port_number=port,
            protocol="tcp",
        )

    def _critical(self, port: int, title: str, description: str, evidence: list[str]) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title=title,
            description=description,
            evidence="; ".join(evidence),
            remediation=(
                "Set a real API auth backend immediately (api.auth_backend to session/basic auth or an SSO "
                "provider) and block the webserver at the network edge. Treat every credential stored in Airflow "
                "connections and variables as compromised and rotate it. Review DAG run history for runs an "
                "attacker may have triggered, and enable audit logging."
            ),
            references=REFERENCES,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            port_number=port,
            protocol="tcp",
        )
