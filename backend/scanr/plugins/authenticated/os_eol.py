"""End-of-life operating system detection over authenticated SSH.

An OS past its vendor support date stops receiving security errata entirely.
Every kernel, glibc, OpenSSL and systemd CVE published after that date stays
open on the host, and no amount of `apt upgrade` will close them — the
repositories simply have nothing newer to offer. That makes the distro release
itself the finding, independent of any individual package version.

Support windows are stored as dates and compared against ``date.today()`` so the
table stays correct as releases age out without anyone editing a boolean. A
distro or version missing from the table produces no finding: guessing would
mean false positives on releases newer than this file.

Strictly read-only — reads /etc/os-release and `uname -r`, nothing else.
"""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import date
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# Vendor end-of-support dates, keyed by os-release ID then by VERSION_ID.
#
# Ubuntu uses the *standard* LTS window, not ESM: ESM is a paid add-on and its
# absence is the common case, so treating it as the default would silently
# suppress real findings.
#
# Debian uses the LTS (not the regular security) window, which is the opposite
# tradeoff: LTS is free and enabled by default in Debian's repositories, so
# reporting a release the moment regular security support lapses would flag
# hosts that are still getting patches.
OS_EOL: dict[str, dict[str, date]] = {
    "ubuntu": {
        "10.04": date(2015, 4, 30),
        "12.04": date(2017, 4, 28),
        "14.04": date(2019, 4, 30),
        "16.04": date(2021, 4, 30),
        "18.04": date(2023, 5, 31),
        "20.04": date(2025, 5, 31),
        "22.04": date(2027, 6, 1),
        "24.04": date(2029, 5, 31),
        # Interim releases carry a nine-month window.
        "20.10": date(2021, 7, 22),
        "21.04": date(2022, 1, 20),
        "21.10": date(2022, 7, 14),
        "22.10": date(2023, 7, 20),
        "23.04": date(2024, 1, 25),
        "23.10": date(2024, 7, 11),
        "24.10": date(2025, 7, 10),
        "25.04": date(2026, 1, 15),
        "25.10": date(2026, 7, 9),
    },
    "debian": {
        "7": date(2018, 5, 31),
        "8": date(2020, 6, 30),
        "9": date(2022, 6, 30),
        "10": date(2024, 6, 30),
        "11": date(2026, 8, 31),
        "12": date(2028, 6, 30),
        "13": date(2030, 6, 30),
    },
    "rhel": {
        "5": date(2017, 3, 31),
        "6": date(2020, 11, 30),
        "7": date(2024, 6, 30),
        "8": date(2029, 5, 31),
        "9": date(2032, 5, 31),
        "10": date(2035, 5, 31),
    },
    "centos": {
        "5": date(2017, 3, 31),
        "6": date(2020, 11, 30),
        # CentOS 8 was cancelled and died three years early; CentOS Stream 8
        # then ended in 2024. Both are reported off the same VERSION_ID.
        "7": date(2024, 6, 30),
        "8": date(2021, 12, 31),
        "9": date(2027, 5, 31),
    },
    "alpine": {
        "3.10": date(2021, 5, 1),
        "3.11": date(2021, 11, 1),
        "3.12": date(2022, 5, 1),
        "3.13": date(2022, 11, 1),
        "3.14": date(2023, 5, 1),
        "3.15": date(2023, 11, 1),
        "3.16": date(2024, 5, 23),
        "3.17": date(2024, 11, 22),
        "3.18": date(2025, 5, 9),
        "3.19": date(2025, 11, 1),
        "3.20": date(2026, 4, 1),
        "3.21": date(2026, 11, 1),
        "3.22": date(2027, 5, 1),
    },
    "amzn": {
        "2018.03": date(2023, 12, 31),
        "2": date(2026, 6, 30),
        "2023": date(2028, 3, 15),
    },
}

# Rebuilds that track Red Hat's lifecycle release-for-release.
_RHEL_REBUILDS = ("rocky", "almalinux")
for _rebuild in _RHEL_REBUILDS:
    OS_EOL[_rebuild] = OS_EOL["rhel"]

_PRETTY_NAMES = {
    "ubuntu": "Ubuntu",
    "debian": "Debian",
    "rhel": "Red Hat Enterprise Linux",
    "centos": "CentOS",
    "rocky": "Rocky Linux",
    "almalinux": "AlmaLinux",
    "alpine": "Alpine Linux",
    "amzn": "Amazon Linux",
}

_VENDOR_LIFECYCLE = {
    "ubuntu": "https://ubuntu.com/about/release-cycle",
    "debian": "https://wiki.debian.org/LTS",
    "rhel": "https://access.redhat.com/support/policy/updates/errata",
    "centos": "https://www.redhat.com/en/topics/linux/centos-linux-eol",
    "rocky": "https://wiki.rockylinux.org/rocky/version/",
    "almalinux": "https://wiki.almalinux.org/release-notes/",
    "alpine": "https://alpinelinux.org/releases/",
    "amzn": "https://docs.aws.amazon.com/linux/al2023/ug/release-cadence.html",
}

# How far past end-of-life before the backlog of unpatched CVEs stops being a
# maintenance problem and starts being an exposure with public exploits.
_CRITICAL_AFTER_DAYS = 1095  # ~3 years of unpatched kernel/libc CVEs
_HIGH_AFTER_DAYS = 0         # any time past end of support
# Warn while there is still time to plan the upgrade.
_APPROACHING_DAYS = 180

_OS_RELEASE_LINE = re.compile(r"^([A-Z_]+)=(.*)$")

_OS_RELEASE_CMD = "cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null"
_KERNEL_CMD = "uname -r 2>/dev/null"


def parse_os_release(text: str | None) -> dict[str, str]:
    """Parse os-release key=value pairs, stripping the optional quoting."""
    parsed: dict[str, str] = {}
    if not text:
        return parsed
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _OS_RELEASE_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        parsed[key] = value
    return parsed


def lookup_eol(distro_id: str | None, version_id: str | None) -> date | None:
    """Return the support end date for a release, or None when unknown.

    VERSION_ID granularity differs per distro (``7.9`` on RHEL, ``3.18.4`` on
    Alpine, ``20.04`` on Ubuntu), so progressively shorter prefixes are tried
    and the first key present in the table wins.
    """
    if not distro_id or not version_id:
        return None
    table = OS_EOL.get(distro_id.strip().lower())
    if not table:
        return None
    parts = version_id.strip().split(".")
    for length in range(len(parts), 0, -1):
        candidate = ".".join(parts[:length])
        if candidate in table:
            return table[candidate]
    return None


def assess(eol: date, today: date) -> tuple[Severity, int] | None:
    """Classify a support window, or None when it needs no finding.

    Returns the severity and days past end-of-life (negative while supported).
    """
    days_past = (today - eol).days
    if days_past >= _CRITICAL_AFTER_DAYS:
        return Severity.critical, days_past
    if days_past >= _HIGH_AFTER_DAYS:
        return Severity.high, days_past
    if days_past >= -_APPROACHING_DAYS:
        return Severity.low, days_past
    return None


class OsEolPlugin(PluginBase):
    id = "authenticated.os_eol"
    name = "End-of-Life Operating System"
    description = "Detect a distro release past its vendor security-support date over SSH"
    category = PluginCategory.authenticated
    severity = Severity.high
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

        output = await self._run_commands(
            host.ip, port, cred, [_OS_RELEASE_CMD, _KERNEL_CMD]
        )
        release = parse_os_release(output.get(_OS_RELEASE_CMD))
        if not release:
            return []

        distro_id = release.get("ID")
        version_id = release.get("VERSION_ID")
        eol = lookup_eol(distro_id, version_id)
        if eol is None:
            # Unknown distro, rolling release, or a version newer than the
            # table. Reporting on a guess here would be worse than silence.
            logger.debug(
                "No support window known for ID=%s VERSION_ID=%s on %s",
                distro_id, version_id, host.ip,
            )
            return []

        verdict = assess(eol, date.today())
        if verdict is None:
            return []

        return [self._build_finding(release, eol, verdict, output.get(_KERNEL_CMD), port)]

    @staticmethod
    def _ssh_port(host: "Host") -> int | None:
        """First open SSH port. One session answers for the whole host, so
        auditing 22 and 2222 separately would only duplicate findings."""
        for port in host.ports:
            if port.number in (22, 2222) and port.state == "open":
                return port.number
        return None

    def _build_finding(
        self,
        release: dict[str, str],
        eol: date,
        verdict: tuple[Severity, int],
        kernel: str | None,
        port_number: int,
    ) -> FindingData:
        severity, days_past = verdict
        distro_id = release.get("ID", "")
        version_id = release.get("VERSION_ID", "")
        pretty = release.get("PRETTY_NAME") or (
            f"{_PRETTY_NAMES.get(distro_id, distro_id)} {version_id}"
        )
        label = f"{_PRETTY_NAMES.get(distro_id, distro_id)} {version_id}"

        if days_past >= 0:
            years, months = days_past // 365, days_past % 365 // 30
            title = f"End-of-Life Operating System ({label})"
            state = (
                f"{label} reached end of security support on {eol.isoformat()}, "
                f"{years} year(s) and {months} month(s) ago. The vendor publishes no "
                "further security errata for this release, so every kernel, glibc, "
                "OpenSSL and userspace vulnerability disclosed since that date is "
                "permanently unpatched on this host — a fully patched machine and an "
                "unpatched one are now the same machine. An attacker with any local "
                "foothold has a long, public, well-tooled list of privilege-escalation "
                "options; a remote one has the same for every exposed service."
            )
        else:
            title = f"Operating System Approaching End of Life ({label})"
            state = (
                f"{label} reaches end of security support on {eol.isoformat()}, in "
                f"{-days_past} days. After that date no further security errata are "
                "published for this release."
            )

        evidence_lines = [f"/etc/os-release: ID={distro_id} VERSION_ID={version_id}"]
        if pretty:
            evidence_lines.append(f"PRETTY_NAME={pretty}")
        if kernel:
            evidence_lines.append(f"uname -r: {kernel.strip()[:120]}")
        evidence_lines.append(f"Vendor support ended: {eol.isoformat()}")

        references = ["https://endoflife.date/"]
        vendor = _VENDOR_LIFECYCLE.get(distro_id)
        if vendor:
            references.insert(0, vendor)

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=title,
            description=state,
            evidence="\n".join(evidence_lines),
            remediation=(
                f"Upgrade this host to a {_PRETTY_NAMES.get(distro_id, distro_id)} "
                "release that is still within its vendor support window, or rebuild it "
                "on a supported base image if it is disposable infrastructure. Where an "
                "in-place upgrade is not possible before the next maintenance window, "
                "purchase extended support if the vendor offers it (Ubuntu Pro/ESM, "
                "RHEL ELS), and in the meantime restrict inbound network exposure and "
                "local shell access to this host and record it as accepted risk."
            ),
            references=references,
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
        """Run every command over a single SSH session.

        Returns an empty mapping when the host is unreachable or the credential
        is rejected — an unreachable host is not a finding.
        """
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
                    _, stdout, _ = client.exec_command(cmd, timeout=20)
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
