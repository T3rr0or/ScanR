"""Build, artifact and deployment platform exposure.

ScanR covers Jenkins, GitLab, Airflow and Portainer. This covers the rest of the
CI/CD estate: Nexus, Artifactory, Harbor, SonarQube, Argo CD, Rancher, TeamCity,
Gitea and Concourse.

These systems matter out of proportion to their apparent role. An artifact
repository holds the binaries that get deployed, so write access to it is code
execution on every host that pulls from it. A CI server holds the credentials
used to reach production. A code-quality server holds a full copy of the source
and, in its settings, the tokens used to fetch it. A cluster manager *is* the
control plane. Anonymous read on any of them is usually enough to find the
credentials needed for the rest.

Two things are reported separately, because they are not the same finding: that
the platform is reachable, and that it returns data without authentication. The
second is confirmed by reading an API that should require a credential — not
inferred from a login page.

GET requests only. Nothing is uploaded, no credential is submitted, and no
pipeline is triggered.
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
        name="Sonatype Nexus Repository",
        ports=(8081, 8082, 8443, 443, 80),
        identify_paths=("/service/rest/v1/status", "/"),
        identify_markers=("nexus repository manager", "nx-", "nexusui", "sonatype"),
        anon_probes=(
            AnonProbe(
                path="/service/rest/v1/repositories",
                required_markers=('"format"', '"type"'),
                severity=Severity.high,
                meaning=(
                    "the repository list is readable without authentication, so every "
                    "hosted and proxied repository — and the artifacts in them — can be "
                    "enumerated and downloaded"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r"Nexus(?:/|\s+Repository Manager\s+)(\d+\.\d+\.\d+(?:-\d+)?)", re.I),
            re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"', re.I),
        ),
        impact=(
            "A binary repository is a supply-chain position: whoever can write to it "
            "controls what every build and every deployment downloads. Anonymous read "
            "exposes internal packages, which routinely embed credentials and reveal "
            "internal service names, and it also enables dependency-confusion attacks "
            "by revealing exactly which internal package names to squat publicly."
        ),
        remediation=(
            "Disable the anonymous access realm (Security → Anonymous Access) and "
            "remove 'nx-anonymous' from the anonymous role. Put the instance behind "
            "SSO, keep it off the internet, and patch — Nexus has had "
            "path-traversal and authentication-bypass advisories."
        ),
        reference="https://help.sonatype.com/en/configuring-nexus-repository.html",
        notable_cves=("CVE-2024-4956", "CVE-2019-7238"),
    ),
    HttpPlatform(
        name="JFrog Artifactory",
        ports=(8081, 8082, 8443, 443, 80),
        identify_paths=("/artifactory/api/system/ping", "/artifactory/", "/ui/login/", "/"),
        identify_markers=("artifactory", "jfrog", "x-jfrog"),
        anon_probes=(
            AnonProbe(
                path="/artifactory/api/repositories",
                required_markers=('"key"', '"type"'),
                severity=Severity.high,
                meaning=(
                    "the repository list is readable anonymously, so internal artifacts "
                    "can be enumerated and pulled without a credential"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"', re.I),
            re.compile(r"Artifactory/(\d+\.\d+\.\d+)", re.I),
        ),
        impact=(
            "Artifactory holds the deployable artifacts and often the Docker images for "
            "the whole estate. Anonymous read leaks internal package names and their "
            "contents — build scripts, embedded tokens, internal hostnames — and gives "
            "an attacker the inventory needed for a dependency-confusion attack."
        ),
        remediation=(
            "Remove the 'anonymous' user's permissions, or disable anonymous access "
            "entirely under Security Configuration. Require SSO, restrict network "
            "access, and enable 'Hide Existence of Unauthorized Resources' so "
            "repository names are not confirmed to unauthenticated callers."
        ),
        reference="https://jfrog.com/help/r/jfrog-platform-administration-documentation/security-configuration",
    ),
    HttpPlatform(
        name="Harbor Container Registry",
        ports=(80, 443, 8080, 8443),
        identify_paths=("/api/v2.0/systeminfo", "/harbor/sign-in", "/"),
        identify_markers=("harbor", "harbor_version", "goharbor"),
        anon_probes=(
            AnonProbe(
                path="/api/v2.0/projects",
                required_markers=('"project_id"', '"name"'),
                severity=Severity.high,
                meaning=(
                    "the project list is readable anonymously, so container images and "
                    "their tags can be enumerated and pulled"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'"harbor_version"\s*:\s*"(v?\d+\.\d+\.\d+[^"]*)"', re.I),
        ),
        impact=(
            "A container registry's images are the running production workloads. "
            "Anonymous pull exposes application source (images are layer archives, "
            "trivially unpacked), any secret baked into a layer, and the internal "
            "service topology. Harbor has also had a critical unauthenticated "
            "privilege-escalation advisory allowing admin account creation."
        ),
        remediation=(
            "Turn off 'Allow anonymous pull' and make every project private. Integrate "
            "with OIDC, enable content trust and vulnerability scanning on push, and "
            "patch to a current release."
        ),
        reference="https://goharbor.io/docs/latest/administration/",
        notable_cves=("CVE-2022-46463",),
    ),
    HttpPlatform(
        name="SonarQube",
        ports=(9000, 9001, 443, 80, 8080),
        identify_paths=("/api/system/status", "/api/server/version", "/"),
        identify_markers=("sonarqube", '"sonarqube"', "sonar-"),
        anon_probes=(
            AnonProbe(
                path="/api/projects/search",
                required_markers=('"components"',),
                severity=Severity.high,
                meaning=(
                    "the project list is readable anonymously — and on SonarQube that "
                    "normally means the analysed source code is browsable too"
                ),
            ),
            AnonProbe(
                path="/api/settings/values",
                required_markers=('"settings"',),
                severity=Severity.high,
                meaning=(
                    "instance settings are readable anonymously; this section holds SCM "
                    "integration tokens and webhook URLs"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'"version"\s*:\s*"(\d+\.\d+(?:\.\d+)*(?:\.\d+)?)"', re.I),
            re.compile(r"^(\d+\.\d+(?:\.\d+)*)$"),
        ),
        impact=(
            "SonarQube keeps a copy of the source it analyses, along with every issue it "
            "found in that source. Anonymous access therefore hands an attacker both the "
            "code and a pre-built list of its weakest points — including the security "
            "hotspots the developers have not fixed yet. Its settings additionally hold "
            "the SCM tokens used to clone the repositories."
        ),
        remediation=(
            "Set 'Force user authentication' in Administration → Security, which is the "
            "single switch that closes anonymous access to both the UI and the API. Then "
            "review which tokens the instance holds and rotate them, since an anonymous "
            "settings read may already have exposed them."
        ),
        reference="https://docs.sonarsource.com/sonarqube-server/latest/instance-administration/security/",
    ),
    HttpPlatform(
        name="Argo CD",
        ports=(8080, 443, 80, 8083),
        identify_paths=("/api/version", "/auth/login", "/"),
        identify_markers=("argo cd", "argocd", '"Version"'),
        anon_probes=(
            AnonProbe(
                path="/api/v1/applications",
                required_markers=('"items"',),
                severity=Severity.critical,
                meaning=(
                    "the application list is readable without a token, which means the "
                    "GitOps control plane is unauthenticated — the same API deploys "
                    "workloads into the cluster"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'"Version"\s*:\s*"(v?\d+\.\d+\.\d+[^"]*)"', re.I),
        ),
        impact=(
            "Argo CD deploys to the cluster. An unauthenticated API is not an "
            "information leak, it is control of everything Argo CD manages: the "
            "application list names every workload and its source repository, and the "
            "same API creates and synchronises applications. Argo CD has also had "
            "critical authentication-bypass advisories, so an exposed instance needs to "
            "be current as well as authenticated."
        ),
        remediation=(
            "Never expose the Argo CD API server to untrusted networks — reach it "
            "through the cluster (port-forward) or an authenticating ingress. Confirm "
            "the server is not running with '--disable-auth', remove any "
            "'policy.default: role:readonly' grant that applies to anonymous users, "
            "disable 'users.anonymous.enabled', and rotate the admin credential and any "
            "repository credentials the instance holds."
        ),
        reference="https://argo-cd.readthedocs.io/en/stable/operator-manual/security/",
        notable_cves=("CVE-2022-29165", "CVE-2024-21652"),
    ),
    HttpPlatform(
        name="Rancher",
        ports=(443, 80, 8443, 8080),
        identify_paths=("/v3/settings/server-version", "/ping", "/dashboard/", "/"),
        identify_markers=("rancher", "server-version", "cattle"),
        anon_probes=(
            AnonProbe(
                path="/v3/clusters",
                required_markers=('"data"', '"type"'),
                severity=Severity.critical,
                meaning=(
                    "the managed-cluster list is readable without authentication, "
                    "exposing the Kubernetes control plane Rancher fronts"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'"value"\s*:\s*"(v\d+\.\d+\.\d+[^"]*)"', re.I),
        ),
        impact=(
            "Rancher manages Kubernetes clusters and holds credentials for each of them. "
            "Unauthenticated access to its API exposes, and can control, every cluster "
            "it manages. Rancher has also had advisories where cluster credentials were "
            "readable by low-privileged users, so any exposure here should be treated as "
            "affecting the downstream clusters too."
        ),
        remediation=(
            "Put Rancher behind an authenticating proxy or VPN, enable an external auth "
            "provider, and audit global role bindings for grants to unauthenticated or "
            "all-authenticated principals. Rotate downstream cluster credentials if the "
            "API was reachable."
        ),
        reference="https://ranchermanager.docs.rancher.com/pages-for-subheaders/rancher-security",
        notable_cves=("CVE-2021-36782", "CVE-2022-31247"),
    ),
    HttpPlatform(
        name="JetBrains TeamCity",
        ports=(8111, 443, 80, 8080),
        identify_paths=("/login.html", "/app/rest/server", "/"),
        identify_markers=("teamcity", "tc-", "jetbrains"),
        anon_probes=(
            AnonProbe(
                path="/app/rest/projects",
                required_markers=("<projects", "project "),
                severity=Severity.high,
                meaning=(
                    "the project list is readable via the REST API without "
                    "authentication, exposing build configurations and their VCS roots"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'version="(\d+\.\d+(?:\.\d+)?)"', re.I),
            re.compile(r"TeamCity\s+(\d+\.\d+(?:\.\d+)?)", re.I),
        ),
        impact=(
            "A build server executes arbitrary code by design and holds the credentials "
            "used to deploy. TeamCity's 2024 authentication-bypass advisories "
            "(CVE-2024-27198 / CVE-2024-27199) were exploited to create administrator "
            "accounts on internet-facing servers within days of disclosure, so an "
            "exposed instance is a high-priority patching question, not just a "
            "hardening one."
        ),
        remediation=(
            "Patch to a current release and verify no unexpected administrator accounts "
            "or agents exist — an exposed unpatched server may already have been "
            "backdoored. Disable guest login, take the server off the internet, and "
            "rotate every credential stored in its build parameters and connections."
        ),
        reference="https://www.jetbrains.com/privacy-security/issues-fixed/",
        notable_cves=("CVE-2024-27198", "CVE-2024-27199", "CVE-2023-42793"),
    ),
    HttpPlatform(
        name="Gitea / Forgejo",
        ports=(3000, 443, 80, 8080),
        identify_paths=("/api/v1/version", "/explore/repos", "/"),
        identify_markers=("gitea", "forgejo", "powered by gitea"),
        anon_probes=(
            AnonProbe(
                path="/api/v1/repos/search?limit=5",
                required_markers=('"data"', '"full_name"'),
                severity=Severity.medium,
                meaning=(
                    "repositories are listed anonymously; any that are public can be "
                    "cloned by anyone who can reach this host"
                ),
            ),
        ),
        version_patterns=(
            re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"', re.I),
        ),
        impact=(
            "A self-hosted Git forge holds source, commit history and often CI "
            "configuration with secrets. Public repositories on an internet-facing "
            "instance are frequently public by accident rather than intent, and the "
            "history of a repository that was briefly public keeps any credential ever "
            "committed to it."
        ),
        remediation=(
            "Set 'REQUIRE_SIGNIN_VIEW = true' and 'DISABLE_REGISTRATION = true' in "
            "app.ini, and review each repository's visibility. Scan the histories of "
            "anything that was reachable for committed credentials, and rotate what you "
            "find — removing the file does not remove it from history."
        ),
        reference="https://docs.gitea.com/administration/config-cheat-sheet",
    ),
    HttpPlatform(
        name="Concourse CI",
        ports=(8080, 443, 80),
        identify_paths=("/api/v1/info", "/"),
        identify_markers=("concourse", '"worker_version"', "atc"),
        anon_probes=(
            AnonProbe(
                path="/api/v1/teams",
                required_markers=('"name"',),
                severity=Severity.medium,
                meaning="team names are readable without authentication",
            ),
        ),
        version_patterns=(
            re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+)"', re.I),
        ),
        impact=(
            "Concourse pipelines run arbitrary containers and hold the credentials used "
            "to deploy. Anonymous visibility of teams and pipelines reveals the "
            "deployment topology and which repositories and registries the pipelines "
            "reach."
        ),
        remediation=(
            "Configure an auth provider and remove the 'main' team's anonymous access. "
            "Keep the web node off untrusted networks and store pipeline secrets in a "
            "credential manager (Vault, SSM) rather than in pipeline YAML."
        ),
        reference="https://concourse-ci.org/auth.html",
    ),
)

_ALL_PORTS = {port for platform in PLATFORMS for port in platform.ports}


class DevOpsPlatformExposurePlugin(PluginBase):
    id = "services.devops_platform_exposure"
    name = "DevOps Platform Exposure"
    description = (
        "Detect exposed Nexus, Artifactory, Harbor, SonarQube, Argo CD, Rancher, "
        "TeamCity, Gitea and Concourse instances and confirm anonymous API access"
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
            evidence.append("Unauthenticated API access confirmed:")
            for access in anonymous:
                evidence.append(f"  GET {access.url} → 200")
                evidence.append(f"    {access.probe.meaning}")
                evidence.append(f"    response begins: {access.snippet.strip()[:200]}")
        evidence.append("")
        evidence.append("GET requests only; no credential was submitted.")

        description = [
            f"A {platform.name} instance is reachable at {url or f'{ip}:{port}'}"
            + (f" (version {version})." if version else "."),
        ]
        if anonymous:
            description.append(
                "It serves data without authentication. "
                + "; ".join(access.probe.meaning for access in anonymous)
                + "."
            )
        description.append(platform.impact)
        if not anonymous:
            description.append(
                "Authentication appears to be required for the API endpoints tested, so "
                "this is reported as exposure of the service rather than as unauthenticated "
                "access. It remains an authentication surface reachable from this network, "
                "and the version above should be checked against the vendor's advisories."
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
            references=[platform.reference, "https://owasp.org/www-project-top-ten/"],
            cve_ids=list(platform.notable_cves),
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"curl -sk {url or f'https://{ip}:{port}'}"
                + (f" && curl -sk https://{ip}:{port}{platform.anon_probes[0].path}" if platform.anon_probes else "")
            ),
        )

