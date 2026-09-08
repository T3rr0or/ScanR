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

# 8088 = YARN ResourceManager, 8042 = YARN NodeManager,
# 50070 = HDFS NameNode (Hadoop 2.x), 9870 = HDFS NameNode (Hadoop 3.x).
HADOOP_PORTS = [8088, 50070, 9870, 8042]
YARN_RM_PORTS = {8088}
YARN_NM_PORTS = {8042}
NAMENODE_PORTS = {50070, 9870}

REFERENCES = [
    "https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-common/SecureMode.html",
    "https://hadoop.apache.org/docs/stable/hadoop-yarn/hadoop-yarn-site/ResourceManagerRest.html",
    "https://attack.mitre.org/techniques/T1190/",
]


def _client(context: "ScanContext") -> httpx.AsyncClient:
    """Single client factory so tests can swap in a MockTransport."""
    return httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=False, **context.proxy_config())


def _schemes(port: int) -> list[str]:
    # Hadoop web UIs are HTTP unless the cluster runs in HTTPS_ONLY policy.
    return ["http", "https"]


async def _fetch(context, ip: str, port: int, path: str, scheme: str | None = None) -> tuple[str, httpx.Response] | None:
    """GET one path. Returns (url, response), or None when nothing answered.

    GET only. In particular this plugin never calls the ResourceManager's
    new-application/submit endpoints, even though an open RM would accept them.
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


def _auth_enforced(resp: httpx.Response) -> bool:
    """A Kerberos/SPNEGO-protected cluster answers 401 Negotiate."""
    return resp.status_code in (401, 403)


class HadoopExposurePlugin(PluginBase):
    id = "services.hadoop_exposure"
    name = "Hadoop YARN / HDFS Exposure"
    description = "Detect unauthenticated Hadoop YARN ResourceManager, NodeManager, or HDFS NameNode interfaces"
    category = PluginCategory.services
    severity = Severity.critical
    ports = HADOOP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in _open(host, set(HADOOP_PORTS)):
            if port in YARN_RM_PORTS:
                finding = await self._probe_resource_manager(context, host.ip, port)
            elif port in YARN_NM_PORTS:
                finding = await self._probe_node_manager(context, host.ip, port)
            else:
                finding = await self._probe_namenode(context, host.ip, port)
            if finding:
                findings.append(finding)
        return findings

    # ── YARN ResourceManager ────────────────────────────────────────────────
    async def _probe_resource_manager(self, context, ip: str, port: int) -> FindingData | None:
        got = await _fetch(context, ip, port, "/ws/v1/cluster/info")
        if got is None:
            return None
        url, resp = got
        scheme = url.split(":", 1)[0]

        data = _json_dict(resp) if resp.status_code == 200 else None
        info = data.get("clusterInfo") if isinstance(data, dict) else None
        if not isinstance(info, dict) or "resourceManagerVersion" not in info:
            if _auth_enforced(resp):
                return await self._auth_enforced_finding(context, ip, port, scheme, url, resp, "YARN ResourceManager")
            return None

        version = str(info.get("hadoopVersion") or info.get("resourceManagerVersion") or "unknown")
        evidence = [
            f"GET {url} -> HTTP 200, Hadoop {version}, RM state={info.get('state')} "
            f"haState={info.get('haState')}"
        ]

        # Application list confirms the read side of the API is fully open and
        # names the running jobs.
        apps = await _fetch(context, ip, port, "/ws/v1/cluster/apps?limit=1", scheme=scheme)
        if apps and apps[1].status_code == 200 and "apps" in apps[1].text[:4000]:
            evidence.append(f"GET {apps[0]} -> HTTP 200 listing cluster applications")

        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title=f"Hadoop YARN ResourceManager {version} Unauthenticated — Remote Code Execution",
            description=(
                f"The YARN ResourceManager REST API on port {port} answers without authentication, so the cluster "
                "is not running in Kerberos secure mode. This is remote code execution, not just an information "
                "leak: the same unauthenticated API accepts POST /ws/v1/cluster/apps/new-application followed by "
                "an application submission whose launch command is arbitrary shell, and YARN will run that "
                "command on cluster nodes as the yarn/hadoop service user. Automated cryptomining worms have "
                "exploited exactly this for years. The API also discloses the cluster topology, node inventory, "
                "and every running job's name and user. This scan only read cluster info and did not submit an "
                "application."
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Enable Hadoop secure mode with Kerberos authentication (hadoop.security.authentication=kerberos) "
                "and turn on the SPNEGO filter for the web interfaces "
                "(hadoop.http.authentication.type=kerberos). Set yarn.acl.enable=true with an admin ACL, block "
                "ports 8088/8032 at the network edge, and audit the application history for submissions you do "
                "not recognise — assume node-level compromise if any are found."
            ),
            references=REFERENCES,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            port_number=port,
            protocol="tcp",
        )

    # ── YARN NodeManager ────────────────────────────────────────────────────
    async def _probe_node_manager(self, context, ip: str, port: int) -> FindingData | None:
        got = await _fetch(context, ip, port, "/ws/v1/node/info")
        if got is None:
            return None
        url, resp = got
        scheme = url.split(":", 1)[0]

        data = _json_dict(resp) if resp.status_code == 200 else None
        info = data.get("nodeInfo") if isinstance(data, dict) else None
        if not isinstance(info, dict) or "nodeManagerVersion" not in info:
            if _auth_enforced(resp):
                return await self._auth_enforced_finding(context, ip, port, scheme, url, resp, "YARN NodeManager")
            return None

        version = str(info.get("hadoopVersion") or info.get("nodeManagerVersion") or "unknown")
        evidence = [f"GET {url} -> HTTP 200, NodeManager {version}, id={info.get('id')}"]
        containers = await _fetch(context, ip, port, "/ws/v1/node/containers", scheme=scheme)
        if containers and containers[1].status_code == 200 and "container" in containers[1].text[:4000].lower():
            evidence.append(f"GET {containers[0]} -> HTTP 200 listing running containers")

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title=f"Hadoop YARN NodeManager {version} Unauthenticated",
            description=(
                f"A YARN NodeManager answers on port {port} without authentication, confirming the cluster is not "
                "in Kerberos secure mode. An attacker can enumerate the containers running on this worker, the "
                "users who own them, the local directories used for job data, and the ResourceManager address — "
                "which is the actual code-execution target. Container logs served by the NodeManager routinely "
                "contain connection strings and tokens from the jobs themselves."
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Enable Hadoop secure mode with Kerberos and the SPNEGO web filter, restrict NodeManager ports to "
                "the cluster's own network, and verify the ResourceManager is not reachable from user networks."
            ),
            references=REFERENCES,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            port_number=port,
            protocol="tcp",
        )

    # ── HDFS NameNode ───────────────────────────────────────────────────────
    async def _probe_namenode(self, context, ip: str, port: int) -> FindingData | None:
        got = await _fetch(context, ip, port, "/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo")
        if got is None:
            return None
        url, resp = got
        scheme = url.split(":", 1)[0]

        evidence: list[str] = []
        version = ""
        confirmed = False

        data = _json_dict(resp) if resp.status_code == 200 else None
        beans = data.get("beans") if isinstance(data, dict) else None
        if isinstance(beans, list) and beans:
            bean = beans[0] if isinstance(beans[0], dict) else {}
            # NameNodeInfo is unmistakable — no generic JMX endpoint carries it.
            if "NameNode" in str(bean.get("name", "")) or "Version" in bean:
                confirmed = True
                version = str(bean.get("Version", "")).split(",")[0]
                evidence.append(
                    f"GET {url} -> HTTP 200 NameNodeInfo (version={version or 'unknown'}, "
                    f"live nodes reported={bool(bean.get('LiveNodes'))})"
                )

        if not confirmed:
            dfs = await _fetch(context, ip, port, "/dfshealth.html", scheme=scheme)
            if dfs and dfs[1].status_code == 200:
                lowered = dfs[1].text[:20000].lower()
                if "namenode" in lowered and ("hadoop" in lowered or "dfshealth" in lowered):
                    confirmed = True
                    evidence.append(f"GET {dfs[0]} -> HTTP 200 HDFS NameNode UI")
            if not confirmed:
                if _auth_enforced(resp):
                    return await self._auth_enforced_finding(context, ip, port, scheme, url, resp, "HDFS NameNode")
                return None

        label = f"HDFS NameNode {version}".strip()

        # WebHDFS LISTSTATUS on the root is the read-side proof that the whole
        # filesystem is browsable; it is a read-only operation.
        webhdfs = await _fetch(context, ip, port, "/webhdfs/v1/?op=LISTSTATUS", scheme=scheme)
        if webhdfs and webhdfs[1].status_code == 200 and "FileStatus" in webhdfs[1].text[:8000]:
            evidence.append(f"GET {webhdfs[0]} -> HTTP 200 listing the HDFS root directory")
            return FindingData(
                plugin_id=self.id,
                severity=Severity.critical,
                title=f"{label} — WebHDFS Filesystem Readable Without Authentication",
                description=(
                    f"WebHDFS on port {port} returned a directory listing of the HDFS root to an unauthenticated "
                    "client. Because the cluster is not in Kerberos secure mode, WebHDFS accepts a "
                    "caller-supplied user name (?user.name=), so an attacker can read — and, with write "
                    "permissions on any path, overwrite — arbitrary files as any user including the HDFS "
                    "superuser. That is full disclosure of the data lake: raw event data, database exports, and "
                    "the credentials that jobs keep in configuration files on HDFS. Overwriting a job's jar or "
                    "script on HDFS also turns this into code execution the next time that job runs."
                ),
                evidence="; ".join(evidence),
                remediation=(
                    "Enable Hadoop secure mode with Kerberos (hadoop.security.authentication=kerberos) and the "
                    "SPNEGO web filter, or disable WebHDFS (dfs.webhdfs.enabled=false) if it is unused. Enforce "
                    "HDFS permissions and Ranger/ACL policies, restrict NameNode ports to the cluster network, "
                    "and rotate every credential stored on HDFS."
                ),
                references=REFERENCES,
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                port_number=port,
                protocol="tcp",
            )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title=f"{label} Metadata Exposed Without Authentication",
            description=(
                f"The HDFS NameNode web interface on port {port} serves cluster metadata to unauthenticated "
                "clients, which means the cluster's web interfaces are not protected by SPNEGO/Kerberos. An "
                "attacker learns the Hadoop version, the DataNode inventory with internal hostnames and "
                "addresses, capacity and block counts, and the safemode/HA state — the map and the version match "
                "needed to attack the cluster's data path directly, and the DataNode addresses are reachable "
                "targets for block-level reads."
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Enable Hadoop secure mode with Kerberos and the SPNEGO filter for the web UIs "
                "(hadoop.http.authentication.type=kerberos), restrict the NameNode HTTP port to the cluster and "
                "operator networks, and keep the JMX servlet off untrusted interfaces."
            ),
            references=REFERENCES,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            port_number=port,
            protocol="tcp",
        )

    async def _auth_enforced_finding(
        self, context, ip: str, port: int, scheme: str, url: str, resp: httpx.Response, component: str
    ) -> FindingData | None:
        """A 401/403 alone is any web server; confirm Hadoop before reporting."""
        negotiate = "negotiate" in resp.headers.get("www-authenticate", "").lower()
        evidence = [f"GET {url} -> HTTP {resp.status_code}" + (" (WWW-Authenticate: Negotiate)" if negotiate else "")]
        if not negotiate:
            conf = await _fetch(context, ip, port, "/conf", scheme=scheme)
            if not conf or "hadoop" not in conf[1].text[:8000].lower():
                return None
            evidence.append(f"GET {conf[0]} -> Hadoop configuration servlet responded")
        return FindingData(
            plugin_id=self.id,
            severity=Severity.info,
            title=f"Hadoop {component} Detected — Authentication Enforced",
            description=(
                f"A Hadoop {component} was detected on port {port} and rejected the unauthenticated request, "
                "consistent with a cluster running in Kerberos secure mode. No cluster metadata was disclosed. "
                "The interface is still reachable from this network path, so it remains a target if any "
                "authentication filter is ever relaxed."
            ),
            evidence="; ".join(evidence),
            remediation=(
                "Keep secure mode and the SPNEGO web filter enabled, and restrict the Hadoop web ports to the "
                "cluster and operator networks so a configuration regression is not immediately exploitable."
            ),
            references=REFERENCES,
            port_number=port,
            protocol="tcp",
        )
