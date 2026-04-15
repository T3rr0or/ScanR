from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class DockerDaemonUnauthPlugin(PluginBase):
    id = "services.docker_daemon_unauth"
    name = "Docker Daemon Exposed (Unauthenticated)"
    description = "Detect Docker daemon TCP socket exposed without authentication"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [2375, 2376]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in (2375, 2376) or port.state != "open":
                continue
            result = await self._probe(host.ip, port.number)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, ip: str, port: int) -> FindingData | None:
        scheme = "http" if port == 2375 else "https"
        url = f"{scheme}://{ip}:{port}/version"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return None
                data = resp.json()
                if "Version" not in data and "ApiVersion" not in data:
                    return None

                docker_version = data.get("Version", "unknown")
                api_version = data.get("ApiVersion", "unknown")
                os_arch = f"{data.get('Os', '')}/{data.get('Arch', '')}"

                # Try to list containers
                containers_resp = await client.get(f"{scheme}://{ip}:{port}/containers/json?all=1")
                container_count = 0
                if containers_resp.status_code == 200:
                    container_count = len(containers_resp.json())

                return FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="Docker Daemon Exposed Without Authentication",
                    description=(
                        f"The Docker daemon on port {port} is accessible without authentication "
                        f"(Docker {docker_version}, API {api_version}, {os_arch}). "
                        f"{container_count} container(s) visible. "
                        "An attacker can create privileged containers to escape to the host OS."
                    ),
                    evidence=f"GET {url} → Docker {docker_version} API {api_version}; {container_count} containers",
                    remediation=(
                        "Never expose the Docker daemon socket over TCP without TLS client authentication. "
                        "Use Unix socket (/var/run/docker.sock) instead, and restrict access via group membership. "
                        "If TCP is required, enable --tlsverify with client certificates."
                    ),
                    references=[
                        "https://docs.docker.com/engine/security/protect-access/",
                        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5736",
                    ],
                    port_number=port,
                    protocol="tcp",
                )
        except Exception:
            pass
        return None
