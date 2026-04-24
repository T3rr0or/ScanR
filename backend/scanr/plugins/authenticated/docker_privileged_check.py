from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class DockerPrivilegedCheckPlugin(PluginBase):
    id = "authenticated.docker_privileged_check"
    name = "Docker Privileged Container Detection"
    description = "Detect privileged Docker containers via SSH inspection of /proc capabilities"
    category = PluginCategory.authenticated
    severity = Severity.high
    requires_auth = True
    ports = [22]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 22 and p.state == "open" for p in host.ports):
            return []

        creds = context.credential_data or {}
        username = creds.get("username", "")
        password = creds.get("password", "")
        if not username:
            return []

        result = await asyncio.get_event_loop().run_in_executor(
            None, self._check_via_ssh, host.ip, username, password
        )
        return [result] if result else []

    def _check_via_ssh(self, ip: str, username: str, password: str) -> FindingData | None:
        try:
            import paramiko
        except ImportError:
            logger.debug("paramiko not available")
            return None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                ip,
                port=22,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )

            indicators = []
            container_info = {}

            # Check 1: Are we in a container?
            _, stdout, _ = client.exec_command(
                "cat /proc/1/cgroup 2>/dev/null | head -5", timeout=5
            )
            cgroup_out = stdout.read().decode(errors="ignore")
            is_docker = (
                "docker" in cgroup_out
                or "containerd" in cgroup_out
                or "/container/" in cgroup_out
            )
            is_container = is_docker or "kubepods" in cgroup_out

            if not is_container:
                client.close()
                return None  # Not in a container, skip

            container_info["type"] = "docker" if is_docker else "kubernetes/containerd"

            # Check 2: Effective capabilities (CapEff in /proc/1/status)
            _, stdout, _ = client.exec_command(
                "grep CapEff /proc/1/status 2>/dev/null", timeout=5
            )
            cap_out = stdout.read().decode(errors="ignore").strip()
            if cap_out:
                try:
                    cap_hex = cap_out.split()[-1]
                    cap_val = int(cap_hex, 16)
                    if cap_val >= 0x3FFFFFFFFF:
                        indicators.append(
                            f"All Linux capabilities granted (CapEff: {cap_hex}) — privileged container"
                        )
                    elif cap_val > 0x00000000000000FF:
                        indicators.append(
                            f"Elevated capabilities detected (CapEff: {cap_hex})"
                        )
                    container_info["capabilities"] = cap_hex
                except ValueError:
                    pass

            # Check 3: Block devices visible (ls /dev/sda*)
            _, stdout, _ = client.exec_command(
                "ls /dev/sd* /dev/xvd* /dev/nvme* 2>/dev/null", timeout=5
            )
            dev_out = stdout.read().decode(errors="ignore").strip()
            if dev_out:
                indicators.append(f"Host block devices visible: {dev_out[:100]}")

            # Check 4: Host root filesystem mounted
            _, stdout, _ = client.exec_command(
                "mount | grep ' / type '", timeout=5
            )
            mount_out = stdout.read().decode(errors="ignore").strip()
            if mount_out and "overlay" not in mount_out:
                indicators.append(f"Non-overlay root mount: {mount_out[:100]}")

            # Check 5: Docker socket accessible inside container
            _, stdout, _ = client.exec_command(
                "ls -la /var/run/docker.sock 2>/dev/null", timeout=5
            )
            docker_sock = stdout.read().decode(errors="ignore").strip()
            if docker_sock:
                indicators.append(
                    f"Docker socket accessible inside container: {docker_sock}"
                )

            client.close()

            if not indicators:
                return None

            return FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title="Privileged Container or Container Escape Risk Detected",
                description=(
                    f"The SSH session on {ip} appears to be inside a container "
                    f"({container_info.get('type', 'unknown')}) "
                    "with privileged capabilities or container escape indicators. "
                    "A privileged container has full access to the host kernel and can escape to the host OS."
                ),
                evidence=(
                    f"Container type: {container_info.get('type', 'unknown')}\n"
                    + "\n".join(f"• {i}" for i in indicators)
                ),
                remediation=(
                    "Remove --privileged flag from container run commands. "
                    "Use specific --cap-add flags for only required capabilities. "
                    "Enable seccomp profiles and AppArmor/SELinux. "
                    "Do not mount the Docker socket inside containers. "
                    "Use rootless containers where possible."
                ),
                references=[
                    "https://docs.docker.com/engine/security/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
                    "https://www.nccgroup.com/us/our-research/abusing-privileged-and-unprivileged-linux-containers/",
                ],
                port_number=22,
                protocol="tcp",
            )
        except Exception as exc:
            logger.debug("Docker privileged check failed on %s: %s", ip, exc)
            return None
