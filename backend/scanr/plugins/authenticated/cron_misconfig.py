"""Cron privilege-escalation misconfigurations found over authenticated SSH.

cron runs its jobs as the user named in the crontab, and the overwhelming
majority of system jobs run as root. That makes every file cron touches a root
execution primitive: if an unprivileged user can write to a crontab, to a
directory cron reads crontabs from, or to any script a root job invokes, they
do not need an exploit — they wait for the next tick and their code runs as
root. It is one of the most reliable local escalation paths on Linux and one of
the easiest to introduce by accident (`chmod 777` on a deploy directory, a
backup script left owned by the application account).

Two distinct problems are reported:

* Writable cron *configuration* — a world-writable /etc/cron.d, /etc/crontab or
  spool file lets anyone install a new root job outright.
* Writable cron *targets* — a root job whose script is writable by someone
  other than root lets anyone replace the body of an existing root job.

Strictly read-only: `find`, `ls` and `grep` only, and any path taken from the
target's own cron files is validated and shell-quoted before it is used.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# These system-wide paths can install or modify jobs that run as root. The
# per-user spool and cron.allow/deny files are omitted: writable per-user
# crontabs run as their owner, while allow/deny only controls submission.
_CRON_PATHS = (
    "/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly "
    "/etc/cron.monthly"
)

_PERM_CMD = (
    f"find {_CRON_PATHS} -maxdepth 2 -perm -o+w "
    "-exec ls -ldn {} \\; 2>/dev/null | head -50"
)
# grep -H keeps the originating file on every line, which is what tells a
# user-field crontab (/etc/crontab, /etc/cron.d) apart from a spool crontab.
_CONTENT_CMD = (
    "grep -rH '' /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null | head -400"
)
_DROPIN_CMD = (
    "ls -ldn /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* "
    "/etc/cron.monthly/* 2>/dev/null | head -200"
)

# Paths pulled out of the target's own cron files are attacker-influenceable
# input to a command we are about to run. Anything outside this charset is
# dropped rather than escaped, and what survives is still shlex-quoted.
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/+@:=-]{1,255}$")
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
_SCHEDULE_KEYWORDS = {
    "@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily",
    "@midnight", "@hourly",
}

# run-parts targets are already covered by the drop-in listing; recording them
# again as "scripts" would double-report every /etc/cron.daily entry.
_NOT_A_SCRIPT = {
    "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
    "/dev/null", "/bin/sh", "/bin/bash", "/usr/bin/env",
}


def parse_ls_line(line: str) -> tuple[str, int, int, str] | None:
    """Parse one `ls -ldn` line into (mode, uid, gid, path)."""
    fields = line.split(None, 8)
    if len(fields) < 9:
        return None
    mode = fields[0]
    if len(mode) < 10 or mode[0] not in "-lcbspd":
        return None
    try:
        uid, gid = int(fields[2]), int(fields[3])
    except ValueError:
        return None
    path = fields[8].strip()
    if not path.startswith("/"):
        return None
    return mode, uid, gid, path


def writability_issue(mode: str, uid: int, gid: int) -> tuple[Severity, str] | None:
    """Describe who other than root can modify this path, strongest first."""
    if mode[8] == "w":
        return Severity.critical, "world-writable"
    if uid != 0:
        return Severity.high, f"owned by uid {uid}, not root"
    if mode[5] == "w" and gid != 0:
        return Severity.high, f"group-writable by gid {gid}"
    return None


def parse_cron_entry(source: str, line: str) -> tuple[str, str] | None:
    """Return (user, command) for one crontab line, or None if it is not a job.

    /etc/crontab and /etc/cron.d entries carry an explicit user field; per-user
    crontabs under /var/spool/cron do not, and take the user from the filename.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if _ENV_ASSIGNMENT.match(line):
        return None

    has_user_field = source == "/etc/crontab" or source.startswith("/etc/cron.d/")
    spool_user = os.path.basename(source)

    if line.startswith("@"):
        parts = line.split(None, 2 if has_user_field else 1)
        if parts[0].lower() not in _SCHEDULE_KEYWORDS:
            return None
        if has_user_field:
            if len(parts) < 3:
                return None
            return parts[1], parts[2]
        if len(parts) < 2:
            return None
        return spool_user, parts[1]

    field_count = 6 if has_user_field else 5
    parts = line.split(None, field_count)
    if len(parts) <= field_count:
        return None
    # A schedule field is digits and the * , - / step syntax; anything else
    # means this line is not a job (a stray continuation, a malformed entry).
    for field in parts[:5]:
        if not re.fullmatch(r"[\d*,\-/A-Za-z]+", field):
            return None
    if has_user_field:
        return parts[5], parts[6]
    return spool_user, parts[5]


def extract_script_paths(command: str) -> list[str]:
    """Absolute paths a cron command invokes or sources, as candidates to stat."""
    paths: list[str] = []
    for token in command.split():
        token = token.strip("\"'();&|`")
        if not token.startswith("/"):
            continue
        if token in _NOT_A_SCRIPT or not _SAFE_PATH.match(token):
            continue
        if token not in paths:
            paths.append(token)
    return paths[:3]


class CronMisconfigPlugin(PluginBase):
    id = "authenticated.cron_misconfig"
    name = "Cron Privilege Escalation Misconfiguration"
    description = "Detect writable cron files, directories and root-invoked scripts over SSH"
    category = PluginCategory.authenticated
    severity = Severity.high
    requires_auth = True
    ports = [22, 2222]

    _MAX_LISTED = 20
    # Bounds the second command's length regardless of how large the host's
    # crontab set is.
    _MAX_STAT_PATHS = 60

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        cred = context.credential("ssh") or context.credential("generic") or context.credential_data
        if not cred:
            return []
        if cred.get("type") not in (None, "ssh", "generic"):
            return []

        port = self._ssh_port(host)
        if port is None:
            return []

        first = await self._run_commands(
            host.ip, port, cred, [_PERM_CMD, _CONTENT_CMD, _DROPIN_CMD]
        )
        if not first:
            # Unreachable host or rejected credential; not a finding.
            return []

        writable_config = self._writable_config(first.get(_PERM_CMD, ""))
        jobs = self._root_jobs(first.get(_CONTENT_CMD, ""))
        writable_targets = self._dropin_issues(first.get(_DROPIN_CMD, ""))

        candidates = [p for _, paths in jobs for p in paths]
        if candidates:
            stat_cmd = self._stat_command(candidates)
            second = await self._run_commands(host.ip, port, cred, [stat_cmd])
            writable_targets.extend(
                self._script_issues(second.get(stat_cmd, ""), jobs)
            )

        findings: list[FindingData] = []
        if writable_config:
            findings.append(self._config_finding(writable_config, port))
        if writable_targets:
            findings.append(self._target_finding(writable_targets, port))
        return findings

    @staticmethod
    def _ssh_port(host: "Host") -> int | None:
        for port in host.ports:
            if port.number in (22, 2222) and port.state == "open":
                return port.number
        return None

    @staticmethod
    def _writable_config(raw: str) -> list[str]:
        entries = []
        for line in raw.splitlines():
            parsed = parse_ls_line(line)
            if parsed is None:
                continue
            mode, uid, gid, path = parsed
            if path in ("/etc/cron.allow", "/etc/cron.deny"):
                continue
            if path == "/var/spool/cron" or path.startswith("/var/spool/cron/"):
                continue
            kind = "directory" if mode[0] == "d" else "file"
            entries.append(f"{path} ({mode}, {kind}, owner uid {uid}, gid {gid})")
        return entries

    @staticmethod
    def _root_jobs(raw: str) -> list[tuple[str, list[str]]]:
        """Root-owned cron jobs paired with the absolute paths they invoke."""
        jobs: list[tuple[str, list[str]]] = []
        for line in raw.splitlines():
            source, _, content = line.partition(":")
            if not source.startswith("/") or not content:
                continue
            entry = parse_cron_entry(source, content)
            if entry is None:
                continue
            user, command = entry
            if user != "root":
                continue
            paths = extract_script_paths(command)
            if paths:
                jobs.append((f"{source}: {content.strip()[:200]}", paths))
        return jobs

    @staticmethod
    def _dropin_issues(raw: str) -> list[tuple[Severity, str]]:
        """/etc/cron.{hourly,daily,...} scripts always run as root."""
        issues = []
        for line in raw.splitlines():
            parsed = parse_ls_line(line)
            if parsed is None:
                continue
            mode, uid, gid, path = parsed
            if mode[0] == "d":
                continue
            verdict = writability_issue(mode, uid, gid)
            if verdict is None:
                continue
            severity, reason = verdict
            issues.append((
                severity,
                f"{path} is {reason} ({mode}) and is executed as root by "
                f"run-parts {os.path.dirname(path)}",
            ))
        return issues

    def _stat_command(self, paths: list[str]) -> str:
        quoted = " ".join(shlex.quote(p) for p in sorted(set(paths))[: self._MAX_STAT_PATHS])
        return f"ls -ldn {quoted} 2>/dev/null | head -{self._MAX_STAT_PATHS}"

    @staticmethod
    def _script_issues(
        raw: str, jobs: list[tuple[str, list[str]]]
    ) -> list[tuple[Severity, str]]:
        issues: list[tuple[Severity, str]] = []
        for line in raw.splitlines():
            parsed = parse_ls_line(line)
            if parsed is None:
                continue
            mode, uid, gid, path = parsed
            if mode[0] == "d":
                continue
            verdict = writability_issue(mode, uid, gid)
            if verdict is None:
                continue
            severity, reason = verdict
            job = next((j for j, paths in jobs if path in paths), "unknown job")
            issues.append((
                severity,
                f"{path} is {reason} ({mode}) and is executed by root cron job — {job}",
            ))
        return issues

    def _listing(self, items: list[str]) -> str:
        shown = [f"• {item}" for item in items[: self._MAX_LISTED]]
        if len(items) > self._MAX_LISTED:
            shown.append(f"… and {len(items) - self._MAX_LISTED} more")
        return "\n".join(shown)

    def _config_finding(self, entries: list[str], port_number: int) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="World-Writable Cron Configuration",
            description=(
                "Cron configuration files or directories on this host are writable by "
                "every local user. cron executes the jobs it finds there as the user "
                "named in the entry, which for system crontabs is root, so any local "
                "account — including a service account running a network-facing daemon "
                "— can append a job and obtain root at the next scheduled tick. No "
                "exploit is involved; this is cron working exactly as designed on a "
                "file whose permissions are wrong."
            ),
            evidence=self._listing(entries),
            remediation=(
                "Restore restrictive ownership and permissions: `chown root:root` on "
                "each path, then `chmod 644 /etc/crontab`, `chmod 755 /etc/cron.d` and "
                "`chmod 644 /etc/cron.d/*`; per-user spool crontabs should be mode 600 "
                "owned by the corresponding user. Then review the current contents of "
                "each affected file for jobs you did not install — a writable cron path "
                "is a persistence mechanism as often as it is an accident."
            ),
            references=[
                "https://man7.org/linux/man-pages/man5/crontab.5.html",
                "https://cwe.mitre.org/data/definitions/732.html",
                "https://attack.mitre.org/techniques/T1053/003/",
            ],
            port_number=port_number,
            protocol="tcp",
        )

    def _target_finding(
        self, issues: list[tuple[Severity, str]], port_number: int
    ) -> FindingData:
        severity = (
            Severity.critical
            if any(s is Severity.critical for s, _ in issues)
            else Severity.high
        )
        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="Root Cron Jobs Execute Scripts Writable by Non-Root Users",
            description=(
                f"{len(issues)} script(s) executed by root through cron can be modified "
                "by a user other than root. Whoever can write to one of these files "
                "controls the contents of a root shell that the system runs "
                "automatically on a schedule: an attacker with any local foothold "
                "appends a single line, waits for the next run, and holds root — with "
                "the execution attributed to a legitimate scheduled job, which makes it "
                "unremarkable in logs and a durable persistence mechanism."
            ),
            evidence=self._listing([detail for _, detail in issues]),
            remediation=(
                "For every script a root cron job runs, set `chown root:root` and "
                "`chmod 755` (or 700 where it holds secrets), and make sure every "
                "parent directory in its path is also root-owned and not group- or "
                "world-writable — a writable directory allows the file to be replaced "
                "even when the file itself is locked down. Where a script must stay "
                "owned by an application account, run the job as that account instead "
                "of root."
            ),
            references=[
                "https://man7.org/linux/man-pages/man5/crontab.5.html",
                "https://cwe.mitre.org/data/definitions/732.html",
                "https://attack.mitre.org/techniques/T1053/003/",
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
                    _, stdout, _ = client.exec_command(cmd, timeout=30)
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
