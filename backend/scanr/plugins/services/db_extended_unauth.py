"""Unauthenticated access to analytics and distributed database platforms.

ScanR covers the mainstream databases — MySQL, PostgreSQL, MSSQL, Oracle,
MongoDB, Redis, Elasticsearch, Cassandra, CouchDB, ClickHouse, InfluxDB, Neo4j,
Memcached. This covers the next tier, which turns up in data-platform and
analytics estates and ships with authentication disabled by default in several
cases: Trino, Apache Druid, ArangoDB, CockroachDB, RethinkDB and Apache Ignite.

These are not peripheral systems. A query engine like Trino or Druid is deliberately
positioned to read *everything*: it federates the warehouse, the object store and
the operational databases behind one endpoint, and it holds the credentials for
each of them. Unauthenticated access to the query engine is therefore often
broader than unauthenticated access to any single database would be.

Every finding is confirmed by reading an endpoint that returns real data —
datasource lists, database lists, cluster settings — not by a version banner or a
200 on a health check.

Read-only: GET requests only. No query is submitted, no table is read, and no
credential is sent.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.services._http_platform import (
    AnonProbe,
    ConfirmedAccess,
    HttpPlatform,
    highest_severity,
    identify_platform,
    probe_anonymous,
)
from scanr.plugins.services._pentest_common import _open

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


PLATFORMS: tuple[HttpPlatform, ...] = (
    HttpPlatform(
        name="Trino / Presto",
        ports=(8080, 8443, 8081, 443),
        identify_paths=("/v1/info", "/ui/", "/"),
        identify_markers=("trino", "presto", '"coordinator"', '"environment"'),
        anon_probes=(
            AnonProbe(
                path="/v1/query",
                required_markers=("[",),
                severity=Severity.critical,
                meaning=(
                    "the query API answers without authentication — the same endpoint "
                    "submits SQL, so this is unauthenticated query execution across every "
                    "catalog the coordinator federates"
                ),
            ),
            AnonProbe(
                path="/v1/info/state",
                required_markers=("active",),
                severity=Severity.high,
                meaning="the coordinator state API is readable without authentication",
            ),
        ),
        version_patterns=(
            re.compile(r'"nodeVersion"\s*:\s*\{\s*"version"\s*:\s*"([^"]+)"', re.I),
            re.compile(r'"version"\s*:\s*"(\d+[^"]*)"', re.I),
        ),
        impact=(
            "A Trino coordinator is a single endpoint that reads everything it is "
            "connected to: the data lake, the warehouse, object storage and the "
            "operational databases behind each catalog. It holds the credentials for "
            "those systems, so an unauthenticated query interface is not access to one "
            "database — it is delegated access to all of them, with Trino performing the "
            "authentication on the attacker's behalf. 'SHOW CATALOGS' followed by "
            "'SELECT' is the whole attack."
        ),
        remediation=(
            "Enable authentication on the coordinator: set 'http-server.authentication.type' "
            "(PASSWORD, JWT, OAUTH2 or KERBEROS) and require TLS, since Trino refuses "
            "password authentication over plaintext HTTP. Then add access control — a "
            "file-based or Ranger/OPA system access control — so an authenticated user "
            "still only reaches the catalogs they should. Keep the coordinator off "
            "untrusted networks; the worker ports should not be reachable at all from "
            "outside the cluster."
        ),
        reference="https://trino.io/docs/current/security.html",
    ),
    HttpPlatform(
        name="Apache Druid",
        ports=(8081, 8888, 8082, 8090, 443, 80),
        identify_paths=("/status", "/status/properties", "/"),
        identify_markers=("druid", '"druid.', "apache druid"),
        anon_probes=(
            AnonProbe(
                path="/druid/coordinator/v1/datasources",
                required_markers=("[",),
                severity=Severity.high,
                meaning=(
                    "the datasource list is readable without authentication, exposing "
                    "every ingested dataset by name"
                ),
            ),
            AnonProbe(
                path="/status/properties",
                required_markers=("druid.",),
                severity=Severity.high,
                meaning=(
                    "runtime properties are readable without authentication; this "
                    "section commonly contains metadata-store and deep-storage "
                    "credentials"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"', re.I),
        ),
        impact=(
            "Druid ships with authentication disabled, so an exposed cluster is usually "
            "fully open rather than misconfigured. Beyond reading every datasource, its "
            "runtime properties expose the metadata store and deep-storage credentials, "
            "and its indexing API has historically permitted arbitrary code execution "
            "through a task specification — CVE-2021-25646 and the JavaScript "
            "'druid.javascript.enabled' feature both lead there."
        ),
        remediation=(
            "Load the druid-basic-security extension (or Kerberos) and set "
            "'druid.auth.authenticatorChain' — authentication is not enabled by default. "
            "Ensure 'druid.escalator' and an authorizer are configured so internal "
            "communication is authenticated too. Keep 'druid.javascript.enabled' false, "
            "restrict the router/broker to the networks that need them, and never expose "
            "the coordinator or overlord. Rotate the metadata-store and deep-storage "
            "credentials if the properties endpoint was reachable."
        ),
        reference="https://druid.apache.org/docs/latest/operations/security-overview/",
        notable_cves=("CVE-2021-25646", "CVE-2023-25194"),
    ),
    HttpPlatform(
        name="ArangoDB",
        ports=(8529, 8530, 443),
        identify_paths=("/_api/version", "/_db/_system/_admin/aardvark/index.html", "/"),
        identify_markers=("arangodb", "aardvark", '"arango"'),
        anon_probes=(
            AnonProbe(
                path="/_api/database",
                required_markers=('"result"', "_system"),
                severity=Severity.critical,
                meaning=(
                    "the database list is readable without authentication, which on "
                    "ArangoDB means the whole instance is open — the same API reads and "
                    "writes documents"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"', re.I),
        ),
        impact=(
            "ArangoDB's HTTP API is its entire interface: the endpoint that lists "
            "databases is the endpoint that reads and writes documents, and its "
            "JavaScript Foxx microservice framework runs server-side code. "
            "Unauthenticated access is therefore read/write access to all data plus a "
            "code execution path, not just an information leak."
        ),
        remediation=(
            "Never run with '--server.authentication false'. Set a root password, create "
            "per-application users with database-scoped permissions, and bind the server "
            "to an internal interface. Disable the Foxx application store on production "
            "instances and put the web interface (Aardvark) behind a proxy that requires "
            "authentication."
        ),
        reference="https://docs.arangodb.com/stable/operations/security/security-options/",
    ),
    HttpPlatform(
        name="CockroachDB",
        ports=(8080, 8443, 26257),
        identify_paths=("/health", "/_status/vars", "/"),
        identify_markers=("cockroach", "cockroachdb", "sql_conns"),
        anon_probes=(
            AnonProbe(
                path="/_status/vars",
                required_markers=("sql_",),
                severity=Severity.medium,
                meaning=(
                    "the metrics endpoint is readable without authentication, exposing "
                    "cluster topology, query volumes and node inventory"
                ),
            ),
            AnonProbe(
                path="/_admin/v1/settings",
                required_markers=('"key_values"',),
                severity=Severity.high,
                meaning=(
                    "cluster settings are readable without authentication; these include "
                    "sink URLs and integration endpoints"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'build_tag\{tag="(v\d+\.\d+\.\d+)"', re.I),
            re.compile(r'"tag"\s*:\s*"(v\d+\.\d+\.\d+)"', re.I),
        ),
        impact=(
            "The CockroachDB admin interface exposes cluster topology, node inventory "
            "and query statistics, and its settings endpoint reveals changefeed sinks and "
            "integration URLs. A cluster started with '--insecure' has no authentication "
            "and no TLS on the SQL port either, so any client that reaches 26257 connects "
            "as any user, including root."
        ),
        remediation=(
            "Never run a production cluster with '--insecure'. Start nodes with "
            "'--certs-dir' so both the SQL and admin interfaces require TLS client "
            "certificates or passwords, set a password for the root user, and restrict "
            "the admin UI (8080) and SQL port (26257) to the networks that need them."
        ),
        reference="https://www.cockroachlabs.com/docs/stable/security-reference/security-overview",
    ),
    HttpPlatform(
        name="RethinkDB",
        ports=(8080, 8081),
        identify_paths=("/", "/#tables"),
        identify_markers=("rethinkdb", "rethinkdb administration"),
        anon_probes=(
            AnonProbe(
                path="/ajax/reql/",
                required_markers=("{",),
                severity=Severity.high,
                meaning=(
                    "the administration interface's ReQL endpoint answers without "
                    "authentication"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r"rethinkdb[^0-9]{0,12}(\d+\.\d+\.\d+)", re.I),
        ),
        impact=(
            "RethinkDB's administration interface has no authentication of its own and "
            "provides a full ReQL console — read and write access to every table, plus "
            "cluster reconfiguration. It is intended to be bound to localhost."
        ),
        remediation=(
            "Bind the web interface to localhost ('--bind-http 127.0.0.1') and reach it "
            "through an SSH tunnel. Set a password on the admin account, enable TLS on "
            "the driver and cluster ports, and restrict 28015/29015 to application and "
            "cluster hosts."
        ),
        reference="https://rethinkdb.com/docs/security/",
    ),
    HttpPlatform(
        name="Apache Ignite (REST)",
        ports=(8080, 11211, 47500),
        identify_paths=("/ignite?cmd=version", "/ignite?cmd=top", "/"),
        identify_markers=("ignite", '"successstatus"', "successStatus"),
        anon_probes=(
            AnonProbe(
                path="/ignite?cmd=top",
                required_markers=('"response"',),
                severity=Severity.high,
                meaning=(
                    "the cluster topology command answers without authentication, "
                    "exposing every node and cache in the grid"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'"response"\s*:\s*"(\d+\.\d+\.\d+)"', re.I),
        ),
        impact=(
            "Apache Ignite's REST connector exposes cache read and write commands as "
            "well as topology. Ignite also has a documented class-deserialisation "
            "exposure on its binary protocol (CVE-2018-8018 and related), so an "
            "unauthenticated grid is a code-execution risk in addition to a data one."
        ),
        remediation=(
            "Disable the REST connector ('ConnectorConfiguration') unless it is needed, "
            "and where it is, require authentication and TLS. Enable authentication on "
            "the grid itself, restrict the discovery (47500) and communication (47100) "
            "ports to cluster members only, and keep the version current."
        ),
        reference="https://ignite.apache.org/docs/latest/security/authentication",
        notable_cves=("CVE-2018-8018",),
    ),
)

_ALL_PORTS = {port for platform in PLATFORMS for port in platform.ports}


class DbExtendedUnauthPlugin(PluginBase):
    id = "services.db_extended_unauth"
    name = "Analytics / Distributed Database Unauthenticated Access"
    description = (
        "Detect Trino, Druid, ArangoDB, CockroachDB, RethinkDB and Apache Ignite "
        "instances that return data or settings without authentication"
    )
    category = PluginCategory.services
    severity = Severity.high
    ports = sorted(_ALL_PORTS)

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in _open(host, _ALL_PORTS):
            for platform in PLATFORMS:
                if port not in platform.ports:
                    continue
                identified = await identify_platform(context, host.ip, port, platform)
                if identified is None:
                    continue
                reasons, version, url = identified
                anonymous = await probe_anonymous(context, host.ip, port, platform)
                findings.append(
                    self._build_finding(
                        host.ip, port, platform, reasons, version, url, anonymous
                    )
                )
                break  # one platform per port
        return findings

    def _build_finding(
        self,
        ip: str,
        port: int,
        platform: HttpPlatform,
        reasons: list[str],
        version: str,
        url: str,
        anonymous: list[ConfirmedAccess],
    ) -> FindingData:
        if anonymous:
            severity = highest_severity(anonymous)
        elif version:
            severity = Severity.low
        else:
            severity = Severity.info

        evidence = [
            f"{url or f'{ip}:{port}'} identified as {platform.name}:",
            *(f"  - {reason}" for reason in reasons),
        ]
        if version:
            evidence.append(f"  - version disclosed: {version}")
        if anonymous:
            evidence.append("")
            evidence.append("Unauthenticated access confirmed:")
            for access in anonymous:
                evidence.append(f"  GET {access.url} → 200")
                evidence.append(f"    {access.probe.meaning}")
                evidence.append(f"    response begins: {access.snippet.strip()[:200]}")
        evidence.append("")
        evidence.append("GET requests only; no query was submitted and no credential sent.")

        description = [
            f"A {platform.name} instance is reachable at {url or f'{ip}:{port}'}"
            + (f" (version {version})." if version else "."),
        ]
        if anonymous:
            description.append(
                "It returns data without authentication. "
                + "; ".join(access.probe.meaning for access in anonymous)
                + "."
            )
        description.append(platform.impact)
        if not anonymous:
            description.append(
                "The endpoints tested required authentication, so this is reported as "
                "exposure of the service rather than unauthenticated access. It remains a "
                "database service reachable from this network, and the version above is "
                "worth checking against the vendor's advisories."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=(
                f"{platform.name} Accessible Without Authentication"
                if anonymous
                else f"{platform.name} Exposed" + (f" (version {version})" if version else "")
            ),
            description="\n\n".join(description),
            evidence="\n".join(evidence),
            remediation=platform.remediation,
            references=[
                platform.reference,
                "https://attack.mitre.org/techniques/T1078/001/",
            ],
            cve_ids=list(platform.notable_cves),
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"curl -sk {url or f'http://{ip}:{port}'}"
                + (
                    f" && curl -sk 'http://{ip}:{port}{platform.anon_probes[0].path}'"
                    if platform.anon_probes
                    else ""
                )
            ),
        )
