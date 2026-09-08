"""Pending security updates counted over authenticated SSH.

Unauthenticated scanning infers patch level from banners, which is guesswork:
distributions backport fixes without changing the advertised version, so a
"vulnerable" banner is often patched and a "current" one often is not. With a
credential the host can simply be asked, and its own package manager gives the
authoritative answer — how many updates are waiting and how many of those the
vendor has flagged as security.

A backlog of pending security updates is the single best predictor of whether
an exploit that lands tomorrow will work on this host: it measures the gap
between "a fix exists" and "the fix is installed", which is the window every
n-day exploit lives in.

Strictly read-only. apt is queried in simulate mode (`-s`), which resolves the
upgrade without touching the system, and no `apt-get update` / `dnf makecache`
is issued, so the package index is left exactly as the host's own maintenance
schedule left it.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_DETECT_CMD = (
    "for b in apt-get dnf yum apk; do "
    "command -v \"$b\" >/dev/null 2>&1 && echo \"$b\"; done"
)

# apt-check prints "total;security" on stderr, hence the redirect. It is the
# same source the MOTD uses, so its numbers match what an operator sees at login.
_APT_CHECK_CMD = "/usr/lib/update-notifier/apt-check 2>&1"
# Debug::NoLocking lets the simulation run without the dpkg lock, so this does
# not contend with a real apt run in progress.
_APT_SIMULATE_CMD = "apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null"
_APK_CMD = "apk version -l '<' 2>/dev/null"

_APT_CHECK_RE = re.compile(r"^(\d+);(\d+)$")
# "name.arch  version  repo" — the only shape a check-update package line takes.
_YUM_PKG_RE = re.compile(r"^(\S+\.\S+)\s+(\S+)\s+(\S+)\s*$")
_YUM_NOISE = ("Last metadata expiration", "Obsoleting Packages", "Security:")

# Thresholds for how far behind is too far. A single pending security update is
# already an open window; a large backlog means the host is not being patched at
# all, which is a different and worse problem.
_HIGH_SECURITY_COUNT = 25


def parse_apt_check(text: str | None) -> tuple[int, int] | None:
    """Parse apt-check's "total;security" output."""
    if not text:
        return None
    match = _APT_CHECK_RE.match(text.strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def parse_apt_simulate(text: str | None) -> tuple[int, int] | None:
    """Count `Inst` lines from `apt-get -s upgrade`, and the security subset.

    apt names the originating suite in each line's parenthesised repository
    list, so a `-security` pocket there is what marks the update as a security
    update.
    """
    if not text:
        return None
    total = security = 0
    for line in text.splitlines():
        if not line.startswith("Inst "):
            continue
        total += 1
        _, _, tail = line.partition("(")
        if "-security" in tail or "Security" in tail:
            security += 1
    return total, security


def parse_yum_check(text: str | None) -> int | None:
    """Count package lines from `yum/dnf check-update`."""
    if text is None:
        return None
    count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or any(noise in stripped for noise in _YUM_NOISE):
            continue
        # Continuation lines are indented; a real package line is not.
        if line[:1].isspace():
            continue
        if _YUM_PKG_RE.match(stripped):
            count += 1
    return count


def parse_apk_version(text: str | None) -> int | None:
    """Count outdated packages from `apk version -l '<'`."""
    if text is None:
        return None
    count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Installed:"):
            continue
        if "<" in stripped:
            count += 1
    return count


def assess(total: int, security: int | None) -> tuple[Severity, int] | None:
    """Severity for a pending-update backlog, or None when there is nothing to say.

    Returns the severity and the count that drove it.
    """
    if total <= 0:
        return None
    if security is None:
        # apk and a bare check-update cannot separate security updates. The
        # backlog is still worth reporting, but not at a security severity we
        # cannot substantiate.
        return Severity.low, total
    if security >= _HIGH_SECURITY_COUNT:
        return Severity.high, security
    if security >= 1:
        return Severity.medium, security
    return Severity.low, total


class PatchStatusPlugin(PluginBase):
    id = "authenticated.patch_status"
    name = "Pending Security Updates"
    description = "Count outstanding package updates via the host's own package manager"
    category = PluginCategory.authenticated
    severity = Severity.medium
    requires_auth = True
    ports = [22, 2222]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        cred = context.credential("ssh") or context.credential("generic") or context.credential_data
        if not cred:
            return []
        if cred.get("type") not in (None, "ssh", "generic"):
            return []

        port = self._ssh_port(host)
        if port is None:
            return []

        detected = await self._run_commands(host.ip, port, cred, [_DETECT_CMD])
        managers = [m for m in (detected.get(_DETECT_CMD) or "").split() if m]
        if not managers:
            # No recognised package manager, or the host never answered. Either
            # way there is nothing to count and nothing to report.
            return []

        counts = None
        for manager in ("apt-get", "dnf", "yum", "apk"):
            if manager in managers:
                counts = await self._count(host.ip, port, cred, manager)
                if counts is not None:
                    break
        if counts is None:
            return []

        total, security, source = counts
        verdict = assess(total, security)
        if verdict is None:
            return []
        return [self._build_finding(total, security, source, verdict, port)]

    @staticmethod
    def _ssh_port(host: "Host") -> int | None:
        for port in host.ports:
            if port.number in (22, 2222) and port.state == "open":
                return port.number
        return None

    async def _count(
        self, ip: str, port: int, cred: dict, manager: str
    ) -> tuple[int, int | None, str] | None:
        """Return (total, security_or_None, command_used) for one package manager."""
        if manager == "apt-get":
            output = await self._run_commands(
                ip, port, cred, [_APT_CHECK_CMD, _APT_SIMULATE_CMD]
            )
            parsed = parse_apt_check(output.get(_APT_CHECK_CMD))
            if parsed is not None:
                return parsed[0], parsed[1], _APT_CHECK_CMD
            parsed = parse_apt_simulate(output.get(_APT_SIMULATE_CMD))
            if parsed is not None:
                return parsed[0], parsed[1], _APT_SIMULATE_CMD
            return None

        if manager in ("dnf", "yum"):
            total_cmd = f"{manager} -q check-update 2>/dev/null"
            sec_cmd = f"{manager} -q check-update --security 2>/dev/null"
            output = await self._run_commands(ip, port, cred, [total_cmd, sec_cmd])
            total = parse_yum_check(output.get(total_cmd))
            if total is None:
                return None
            # --security needs updateinfo metadata, which not every mirror
            # carries; absent it the security subset stays unknown rather than
            # being silently reported as zero.
            security = parse_yum_check(output.get(sec_cmd))
            if security == 0 and total > 0 and not (output.get(sec_cmd) or "").strip():
                security = None
            return total, security, total_cmd

        if manager == "apk":
            output = await self._run_commands(ip, port, cred, [_APK_CMD])
            total = parse_apk_version(output.get(_APK_CMD))
            if total is None:
                return None
            return total, None, _APK_CMD

        return None

    def _build_finding(
        self,
        total: int,
        security: int | None,
        source: str,
        verdict: tuple[Severity, int],
        port_number: int,
    ) -> FindingData:
        severity, _ = verdict

        if security is None:
            headline = (
                f"{total} package update(s) are pending on this host. This package "
                "manager does not distinguish security updates from the rest, so the "
                "security-relevant subset is unknown and has to be assumed non-empty."
            )
            title = f"Pending Package Updates ({total})"
        elif security > 0:
            headline = (
                f"{security} of {total} pending package update(s) are flagged by the "
                "vendor as security updates. Each one corresponds to a vulnerability "
                "that is already public and already fixed upstream, which is exactly "
                "the class an attacker can reach for with a working, published exploit "
                "and no research of their own."
            )
            title = f"Pending Security Updates ({security})"
        else:
            headline = (
                f"{total} package update(s) are pending, none currently flagged as "
                "security updates. The backlog still matters: it shows the host is "
                "behind its repositories, so the next security advisory will land on "
                "an unpatched machine."
            )
            title = f"Pending Package Updates ({total})"

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=title,
            description=headline,
            evidence=(
                f"Counted with: {source}\n"
                f"Total pending updates: {total}\n"
                f"Security updates: {security if security is not None else 'not reported by this package manager'}"
            ),
            remediation=(
                "Apply the pending updates during the next maintenance window "
                "(`apt-get update && apt-get upgrade`, `dnf upgrade --security`, or "
                "`apk upgrade`), prioritising the security-flagged set, and reboot if "
                "the kernel or glibc was among them. To keep the backlog from "
                "reappearing, enable automated security patching — unattended-upgrades "
                "on Debian/Ubuntu, dnf-automatic with `upgrade_type=security` on "
                "RHEL-family — and alert on hosts whose pending-security count stays "
                "above zero for more than a patch cycle."
            ),
            references=[
                "https://wiki.debian.org/UnattendedUpgrades",
                "https://access.redhat.com/solutions/1189233",
                "https://cwe.mitre.org/data/definitions/1104.html",
            ],
            port_number=port_number,
            protocol="tcp",
        )

    # ── SSH plumbing ─────────────────────────────────────────────────────────

    async def _run_commands(
        self, ip: str, port: int, cred: dict, commands: list[str]
    ) -> dict[str, str]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._ssh_session, ip, port, cred, commands)

    def _ssh_session(
        self, ip: str, port: int, cred: dict, commands: list[str]
    ) -> dict[str, str]:
        """Run every command over a single SSH session; {} when unreachable."""
        results: dict[str, str] = {}
        client = None
        try:
            import paramiko

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": ip,
                "port": port,
                "username": cred.get("username", "root"),
                "timeout": 10,
                "allow_agent": False,
            }
            if cred.get("private_key"):
                import io
                connect_kwargs["pkey"] = paramiko.RSAKey.from_private_key(
                    io.StringIO(cred["private_key"])
                )
            else:
                connect_kwargs["password"] = cred.get("password", "")
                connect_kwargs["look_for_keys"] = False

            client.connect(**connect_kwargs)
            for cmd in commands:
                try:
                    # check-update on a host with cold metadata can take a while.
                    _, stdout, _ = client.exec_command(cmd, timeout=60)
                    results[cmd] = stdout.read().decode(errors="replace")
                except Exception as exc:
                    logger.debug("SSH command failed on %s: %s", ip, exc)
        except Exception as exc:
            logger.debug("SSH session failed %s: %s", ip, exc)
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
        return results
