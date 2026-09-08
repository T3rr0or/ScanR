"""Unexpected SUID/SGID binaries discovered over authenticated SSH.

A set-user-ID binary runs with the file owner's privileges regardless of who
launches it, so a SUID-root binary is a deliberate, permanent privilege
boundary crossing. Distributions ship a small, well-known set of them (su,
sudo, passwd, mount, ping and friends) and everything beyond that set was put
there by someone — a package, an installer, or an attacker leaving a back door.

Two classes are separated because they mean very different things:

* A general-purpose tool with SUID root — nmap, vim, find, python, perl, bash,
  more, less, awk — is not a subtle weakness. Each of these has a documented
  one-liner (GTFOBins) that drops straight to an interactive root shell, so any
  user who can log in is already root.
* Anything else outside the baseline is unexplained privilege and worth
  reviewing, but needs a human to judge whether the vendor put it there.

Strictly read-only: a single `find ... -exec ls -ldn` traversal.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# -xdev keeps the walk on the root filesystem, which also skips /proc, /sys and
# any network mount. POSIX -perm -4000 / -perm -2000 and -exec ... \; are used
# instead of the GNU-only -perm /6000 and -printf so this also works under
# busybox find on Alpine.
_FIND_CMD = (
    "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) "
    "-exec ls -ldn {} \\; 2>/dev/null | head -300"
)

# Directories a distribution legitimately ships SUID/SGID binaries in. A
# baseline name found anywhere else — a SUID `mount` under /home or /tmp — is
# an impostor and stays reported.
_SYSTEM_BIN_DIRS = (
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib",
    "/usr/lib64", "/lib", "/lib64", "/usr/local/libexec",
)

# Binaries mainstream distributions ship SUID or SGID by design.
_BASELINE = frozenset({
    # setuid core
    "su", "sudo", "sudoedit", "passwd", "chsh", "chfn", "gpasswd", "newgrp",
    "chage", "expiry", "mount", "umount", "ping", "ping6", "pkexec",
    "newuidmap", "newgidmap", "fusermount", "fusermount3", "unix_chkpwd",
    "pam_timestamp_check", "usernetctl", "mount.nfs", "mount.nfs4",
    "umount.nfs", "umount.nfs4", "mount.cifs", "ssh-keysign", "ssh-agent",
    "dbus-daemon-launch-helper", "polkit-agent-helper-1", "utempter",
    "Xorg.wrap", "Xorg", "vmware-user-suid-wrapper", "suexec",
    # setgid core
    "wall", "write", "bsd-write", "at", "crontab", "locate", "mlocate",
    "plocate", "sg", "dotlockfile", "postdrop", "postqueue", "ssh-askpass",
    "chrome-sandbox", "man", "mandb", "screen",
})

# Interactive-capable tools whose GTFOBins entry is a root shell. Matched on the
# basename with the version suffix stripped, so python3.11 and perl5.36 land
# here too.
_ESCALATION = frozenset({
    "awk", "gawk", "mawk", "nawk", "bash", "sh", "dash", "zsh", "ksh", "csh",
    "tcsh", "ash", "busybox", "vi", "vim", "vimdiff", "rvim", "view", "nvim",
    "emacs", "nano", "pico", "ed", "ex", "less", "more", "man", "find",
    "nmap", "perl", "python", "ruby", "php", "lua", "node", "tclsh", "expect",
    "gdb", "strace", "ltrace", "socat", "nc", "ncat", "netcat", "tcpdump",
    "env", "make", "cmake", "git", "docker", "systemctl", "journalctl",
    "service", "start-stop-daemon", "flock", "ionice", "nice", "nohup",
    "setarch", "stdbuf", "taskset", "time", "timeout", "watch", "xargs",
    "script", "rsync", "tar", "zip", "unzip", "gzip", "bzip2", "cpio", "dd",
    "cp", "mv", "chmod", "chown", "chroot", "install", "tee", "sed",
    "openssl", "wget", "curl", "ftp", "smbclient", "mysql", "psql", "sqlite3",
    "pip", "easy_install", "cpan", "gem", "npm", "apt", "apt-get",
    "dpkg", "yum", "dnf", "rpm", "zypper", "apk", "crash", "dmsetup",
    "ldconfig", "logsave", "vigr", "vipw", "byebug", "jq", "ip", "iftop",
})


def strip_version_suffix(name: str) -> str:
    """`python3.11` -> `python`, `perl5.36.0` -> `perl`, `awk` -> `awk`."""
    trimmed = name.rstrip("0123456789.")
    # Only trust the trim when something recognisable is left; `7z` must not
    # become an empty string.
    return trimmed or name


def parse_ls_line(line: str) -> tuple[str, int, int, str] | None:
    """Parse one `ls -ldn` line into (mode, uid, gid, path).

    Returns None for header/summary lines and anything that does not look like
    a long listing, so a busybox quirk degrades to "found nothing" rather than
    an exception.
    """
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


def _is_setuid(mode: str) -> bool:
    return mode[3] in ("s", "S")


def _is_setgid(mode: str) -> bool:
    return mode[6] in ("s", "S")


def _in_system_dir(path: str) -> bool:
    directory = os.path.dirname(path)
    return any(
        directory == base or directory.startswith(base + "/")
        for base in _SYSTEM_BIN_DIRS
    )


def classify(entries: list[tuple[str, int, int, str]]) -> tuple[list[str], list[str]]:
    """Split parsed listings into (escalation, unexpected) human-readable lines.

    Baseline binaries in their normal system directories are dropped entirely.
    """
    escalation: list[str] = []
    unexpected: list[str] = []

    for mode, uid, gid, path in entries:
        setuid, setgid = _is_setuid(mode), _is_setgid(mode)
        if not setuid and not setgid:
            continue
        name = os.path.basename(path)
        base_name = strip_version_suffix(name)
        in_system_dir = _in_system_dir(path)

        bits = "SUID" if setuid else "SGID"
        if setuid and setgid:
            bits = "SUID+SGID"
        owner = f"uid={uid}" if uid else "root"
        detail = f"{path} ({mode}, {bits}, owner {owner}, gid={gid})"

        if (name in _BASELINE or base_name in _BASELINE) and in_system_dir:
            # Shipped this way by the distribution. The exception is a binary
            # that is baseline only because it is normally SGID (man, screen):
            # SUID *root* on one of those is an escalation whoever set it.
            if not (setuid and uid == 0 and base_name in _ESCALATION):
                continue

        if setuid and uid == 0 and base_name in _ESCALATION:
            escalation.append(detail)
        else:
            unexpected.append(detail)

    return escalation, unexpected


class SuidBinariesPlugin(PluginBase):
    id = "authenticated.suid_binaries"
    name = "Unexpected SUID/SGID Binaries"
    description = "Find SUID/SGID binaries outside the distribution baseline over SSH"
    category = PluginCategory.authenticated
    severity = Severity.medium
    requires_auth = True
    ports = [22, 2222]

    # Keep the finding readable; the full list belongs in the operator's own
    # `find` run, which the remediation text hands them.
    _MAX_LISTED = 25

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        cred = context.credential("ssh") or context.credential("generic") or context.credential_data
        if not cred:
            return []
        if cred.get("type") not in (None, "ssh", "generic"):
            return []

        port = self._ssh_port(host)
        if port is None:
            return []

        output = await self._run_commands(host.ip, port, cred, [_FIND_CMD])
        raw = output.get(_FIND_CMD)
        if not raw or not raw.strip():
            # Either the host is unreachable or the account cannot traverse the
            # filesystem. Neither is a finding on its own.
            return []

        entries = [
            parsed for line in raw.splitlines()
            if (parsed := parse_ls_line(line)) is not None
        ]
        if not entries:
            return []

        escalation, unexpected = classify(entries)
        findings: list[FindingData] = []
        if escalation:
            findings.append(self._escalation_finding(escalation, port))
        if unexpected:
            findings.append(self._unexpected_finding(unexpected, port))
        return findings

    @staticmethod
    def _ssh_port(host: "Host") -> int | None:
        for port in host.ports:
            if port.number in (22, 2222) and port.state == "open":
                return port.number
        return None

    def _listing(self, items: list[str]) -> str:
        shown = [f"• {item}" for item in items[: self._MAX_LISTED]]
        if len(items) > self._MAX_LISTED:
            shown.append(f"… and {len(items) - self._MAX_LISTED} more")
        return "\n".join(shown)

    def _escalation_finding(self, items: list[str], port_number: int) -> FindingData:
        names = ", ".join(sorted({os.path.basename(i.split(" (")[0]) for i in items}))
        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="SUID Root Binaries Allowing Trivial Privilege Escalation",
            description=(
                f"General-purpose tools are installed set-user-ID root on this host: "
                f"{names}. Each of these can execute arbitrary commands or spawn a "
                "shell as part of its normal, documented behaviour, so the SUID bit "
                "hands a complete root shell to every user who can log in — no "
                "exploit, no memory corruption, a single published one-liner. This "
                "collapses the boundary between any low-privilege foothold (a "
                "compromised service account, a stolen SSH key, a web shell) and full "
                "control of the machine."
            ),
            evidence=self._listing(items),
            remediation=(
                "Remove the set-user-ID bit from these binaries: `chmod u-s <path>`. "
                "If a specific user genuinely needs to run one of them with elevated "
                "privileges, express that as a narrowly scoped sudoers rule for the "
                "exact command and arguments instead — sudo logs the invocation and "
                "can be restricted, a SUID bit can do neither. Afterwards confirm "
                "with `find / -xdev -perm -4000 -type f -exec ls -ld {} \\;` and "
                "investigate how the bit was set, since an attacker-planted SUID "
                "binary is a common persistence mechanism."
            ),
            references=[
                "https://gtfobins.github.io/#+suid",
                "https://cwe.mitre.org/data/definitions/250.html",
                "https://man7.org/linux/man-pages/man2/setuid.2.html",
            ],
            port_number=port_number,
            protocol="tcp",
        )

    def _unexpected_finding(self, items: list[str], port_number: int) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title="SUID/SGID Binaries Outside the Distribution Baseline",
            description=(
                f"{len(items)} set-user-ID or set-group-ID file(s) are present that no "
                "mainstream distribution ships by default. Each one runs with its "
                "owner's privileges rather than the caller's, so any memory-safety or "
                "argument-handling bug in it becomes a local privilege escalation. "
                "Unexplained SUID files are also a standard persistence technique: an "
                "attacker who briefly held root often leaves a SUID copy of a shell or "
                "a small helper behind to get it back."
            ),
            evidence=self._listing(items),
            remediation=(
                "Review each file and confirm it was installed by a package: "
                "`dpkg -S <path>` or `rpm -qf <path>`. Anything with no owning package "
                "should be treated as suspicious and investigated before removal. "
                "Where the elevated privilege is not required, clear the bits with "
                "`chmod u-s,g-s <path>`; where it is, prefer file capabilities "
                "(`setcap`) or a scoped sudoers rule over a blanket SUID root."
            ),
            references=[
                "https://gtfobins.github.io/#+suid",
                "https://cwe.mitre.org/data/definitions/732.html",
                "https://attack.mitre.org/techniques/T1548/001/",
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
                    # A full-filesystem find is slow on large hosts; the head(1)
                    # cap bounds the output, not the walk.
                    _, stdout, _ = client.exec_command(cmd, timeout=120)
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
