"""Windows servicing status over authenticated SMB.

Unauthenticated fingerprinting of a Windows host gives a major/minor version at
best. The build and update-revision numbers are what actually decide whether a
published exploit works, and they are sitting in the registry where a credential
can simply read them.

Two questions are answered from that:

* **Is this build still serviced?** A Windows release past end of servicing gets no
  security updates at all, so every subsequent vulnerability stays open. That is a
  property of the release, independent of how diligently the host is patched, and
  it is compared against today's date so the table stays correct as releases age
  out.
* **How far behind is the update revision?** The UBR increments with each monthly
  cumulative update. Comparing it against the latest revision known to this file
  gives a lower bound on how long the host has gone unpatched.

The second answer carries an explicit caveat, because the reference data ages: a
host *newer* than this file is never reported, and the "as of" date is stated in
the finding so a reader knows how much to trust the gap. Understating is the
deliberate choice — a false "up to date" is recoverable, a false "months behind"
wastes a remediation cycle.

Strictly read-only: three registry values, no commands, and the RemoteRegistry
service is never started.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.authenticated._windows import (
    HKLM,
    RegistryReader,
    smb_port_open,
    windows_credential,
)

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_CURRENT_VERSION_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_VALUE_NAMES = (
    "CurrentBuildNumber",
    "CurrentBuild",
    "UBR",
    "DisplayVersion",
    "ReleaseId",
    "ProductName",
    "InstallationType",
    "EditionID",
)


@dataclass(frozen=True)
class Release:
    """One Windows release: what to call it, and when its servicing ends."""

    name: str
    end_of_servicing: date
    # Latest update revision known when this table was last reviewed.
    latest_ubr: int = 0


# Keyed by the build number in CurrentBuild. Client and server releases share
# build numbers, so the name covers both where that is the case.
#
# Dates are end of *security* servicing for the mainstream edition — Enterprise
# and Education windows where those differ, since those are what appear in a
# managed estate. Where a release has ended, the date is historical and the
# comparison against today's date makes the finding self-maintaining.
REFERENCE_DATE = date(2026, 9, 1)

RELEASES: dict[str, Release] = {
    # Windows 10
    "10240": Release("Windows 10 1507 (LTSB)", date(2025, 10, 14), 20348),
    "14393": Release("Windows 10 1607 / Server 2016 (LTSB/LTSC)", date(2027, 1, 12), 8148),
    "17763": Release("Windows 10 1809 / Server 2019 (LTSC)", date(2029, 1, 9), 7792),
    "18362": Release("Windows 10 1903", date(2020, 12, 8), 1256),
    "18363": Release("Windows 10 1909", date(2021, 5, 11), 2274),
    "19041": Release("Windows 10 2004", date(2021, 12, 14), 1288),
    "19042": Release("Windows 10 20H2", date(2023, 5, 9), 2965),
    "19043": Release("Windows 10 21H1", date(2022, 12, 13), 2364),
    "19044": Release("Windows 10 21H2", date(2024, 6, 11), 4651),
    "19045": Release("Windows 10 22H2", date(2025, 10, 14), 6332),
    # Windows 11
    "22000": Release("Windows 11 21H2", date(2024, 10, 8), 3260),
    "22621": Release("Windows 11 22H2", date(2025, 10, 14), 5624),
    "22631": Release("Windows 11 23H2", date(2026, 11, 10), 5624),
    "26100": Release("Windows 11 24H2 / Server 2025", date(2029, 10, 9), 6584),
    # Windows Server
    "20348": Release("Windows Server 2022", date(2031, 10, 14), 3932),
    "25398": Release("Windows Server 23H2", date(2025, 10, 24), 1611),
    # End of life
    "9600": Release("Windows 8.1 / Server 2012 R2", date(2023, 10, 10), 0),
    "9200": Release("Windows 8 / Server 2012", date(2023, 10, 10), 0),
    "7601": Release("Windows 7 SP1 / Server 2008 R2 SP1", date(2020, 1, 14), 0),
    "6002": Release("Windows Vista SP2 / Server 2008 SP2", date(2020, 1, 14), 0),
    "3790": Release("Windows Server 2003", date(2015, 7, 14), 0),
}

# Roughly one cumulative update per month; the UBR gap is converted to a rough
# number of missed cycles rather than presented as a raw number nobody can read.
_UBR_HIGH_GAP = 3
_UBR_MEDIUM_GAP = 1


@dataclass
class WindowsBuild:
    build: str = ""
    ubr: int | None = None
    display_version: str = ""
    product_name: str = ""
    installation_type: str = ""
    edition: str = ""

    @property
    def full_version(self) -> str:
        if self.ubr is None:
            return self.build
        return f"{self.build}.{self.ubr}"

    @property
    def is_server(self) -> bool:
        return self.installation_type.lower() == "server" or "server" in self.product_name.lower()


def assess_servicing(release: Release, today: date) -> tuple[Severity, int] | None:
    """Severity and days past end of servicing, or None while still supported."""
    if today <= release.end_of_servicing:
        return None
    days = (today - release.end_of_servicing).days
    # A release that ended years ago is a materially worse position than one that
    # lapsed last month, and the two warrant different urgency.
    return (Severity.critical if days > 365 else Severity.high), days


def assess_update_revision(release: Release, ubr: int | None) -> tuple[Severity, int] | None:
    """Severity and the revision gap, or None when the host is not measurably behind.

    Returns nothing when the host's revision is at or above the newest one this
    table knows, which is also what happens on a host patched more recently than
    this file — deliberately, so stale reference data cannot invent a finding.
    """
    if ubr is None or release.latest_ubr <= 0 or ubr >= release.latest_ubr:
        return None
    gap = release.latest_ubr - ubr
    # The UBR is not a monthly counter, so the gap is only ever used as evidence
    # that the host is behind, never converted into a precise month count.
    if gap >= 1000:
        return Severity.high, gap
    if gap >= 100:
        return Severity.medium, gap
    return Severity.low, gap


class WindowsPatchStatusPlugin(PluginBase):
    id = "authenticated.windows_patch_status"
    name = "Windows Servicing and Update Revision"
    description = (
        "Read the Windows build and update revision over authenticated SMB to "
        "report end-of-servicing releases and hosts behind on cumulative updates"
    )
    category = PluginCategory.authenticated
    severity = Severity.high
    requires_auth = True
    ports = [445]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        port = smb_port_open(host)
        if port is None:
            return []
        credential = windows_credential(context)
        if credential is None:
            return []

        build = await self._read_build(host.ip, port, credential)
        if build is None or not build.build:
            return []

        release = RELEASES.get(build.build)
        if release is None:
            # A build newer than this table. Reporting it would be a guess, and a
            # guess about patch level is worse than silence.
            logger.debug("unknown Windows build %s on %s", build.build, host.ip)
            return []

        findings: list[FindingData] = []
        today = date.today()
        eol = assess_servicing(release, today)
        if eol is not None:
            findings.append(self._eol_finding(host.ip, port, build, release, eol, today))

        behind = assess_update_revision(release, build.ubr)
        if behind is not None:
            findings.append(self._behind_finding(host.ip, port, build, release, behind))
        return findings

    async def _read_build(self, ip: str, port: int, credential) -> WindowsBuild | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._read_sync, ip, port, credential)

    @staticmethod
    def _read_sync(ip: str, port: int, credential) -> WindowsBuild | None:
        reader = RegistryReader(ip=ip, credential=credential, port=port)
        if not reader.open():
            return None
        try:
            values = reader.read_values(HKLM, _CURRENT_VERSION_KEY, _VALUE_NAMES)
        finally:
            reader.close()
        if not values:
            return None

        build_value = values.get("CurrentBuild") or values.get("CurrentBuildNumber")
        ubr_value = values.get("UBR")
        return WindowsBuild(
            build=build_value.as_text().strip() if build_value else "",
            ubr=ubr_value.as_int() if ubr_value else None,
            display_version=values["DisplayVersion"].as_text() if "DisplayVersion" in values else (
                values["ReleaseId"].as_text() if "ReleaseId" in values else ""
            ),
            product_name=values["ProductName"].as_text() if "ProductName" in values else "",
            installation_type=values["InstallationType"].as_text() if "InstallationType" in values else "",
            edition=values["EditionID"].as_text() if "EditionID" in values else "",
        )

    def _identity(self, build: WindowsBuild, release: Release) -> str:
        parts = [release.name]
        if build.display_version and build.display_version not in release.name:
            parts.append(f"({build.display_version})")
        parts.append(f"build {build.full_version}")
        if build.edition:
            parts.append(f"edition {build.edition}")
        return " ".join(parts)

    def _eol_finding(
        self,
        ip: str,
        port: int,
        build: WindowsBuild,
        release: Release,
        verdict: tuple[Severity, int],
        today: date,
    ) -> FindingData:
        severity, days = verdict
        years = days / 365.25
        role = "server" if build.is_server else "workstation"

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=f"Windows Past End of Servicing — {release.name}",
            description=(
                f"This {role} runs {self._identity(build, release)}, whose security "
                f"servicing ended on {release.end_of_servicing.isoformat()} — "
                f"{days} days ago ({years:.1f} years).\n\n"
                "The host receives no security updates. Every Windows vulnerability "
                "published since that date remains open on it and will stay open: there "
                "is no patch to apply, so this is not something Windows Update or a "
                "patch-management tool can resolve. The finding is a property of the "
                "release, not of how well the host is maintained.\n\n"
                "In practice an unserviced Windows host is where an intrusion becomes "
                "persistent. It is reachable from the rest of the estate, it holds "
                "credentials and cached domain tokens like any other member, and the "
                "exploits that work against it are public and reliable. Its presence also "
                "weakens the hosts around it, because credentials used to administer it "
                "are exposed on a machine that cannot be defended.\n\n"
                + (
                    "Server releases in this state are frequently kept for one legacy "
                    "application. That is a scoping problem rather than a patching one, "
                    "and it is worth resolving as such: the application's dependency, not "
                    "the operating system, is what needs the attention."
                    if build.is_server
                    else ""
                )
            ),
            evidence=(
                f"Read over authenticated SMB from {ip}:{port}, registry key "
                f"HKLM\\{_CURRENT_VERSION_KEY}:\n"
                f"  ProductName: {build.product_name or '(not set)'}\n"
                f"  CurrentBuild: {build.build}\n"
                f"  UBR: {build.ubr if build.ubr is not None else '(not set)'}\n"
                f"  DisplayVersion: {build.display_version or '(not set)'}\n"
                f"  InstallationType: {build.installation_type or '(not set)'}\n"
                f"  EditionID: {build.edition or '(not set)'}\n\n"
                f"Identified as {release.name}; end of security servicing "
                f"{release.end_of_servicing.isoformat()}, evaluated against "
                f"{today.isoformat()}."
            ),
            remediation=(
                "Upgrade or replace the host. That is the only remediation — there is no "
                "configuration that restores security updates to an unserviced release.\n\n"
                "Where an in-place upgrade is not immediately possible, contain it "
                "meanwhile: put it in its own network segment with explicit allow rules "
                "for only the traffic it needs, remove it from any group that grants it "
                "rights elsewhere, stop administering it with credentials that are "
                "privileged on other systems (use a dedicated local account), and monitor "
                "it more closely than the rest of the estate rather than less.\n\n"
                "Extended Security Updates are available for some releases as a paid "
                "programme and do restore patches — if the host is enrolled, confirm the "
                "ESU keys are actually active, because an enrolled-but-unactivated host "
                "receives nothing and looks identical to this finding.\n\n"
                "Record the reason the host still exists. An unserviced Windows system "
                "with no owner and no documented dependency is usually one nobody has "
                "tested removing."
            ),
            references=[
                "https://learn.microsoft.com/en-us/lifecycle/products/",
                "https://learn.microsoft.com/en-us/windows/release-health/",
                "https://attack.mitre.org/techniques/T1210/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"reg query \\\\{ip}\\HKLM\\{_CURRENT_VERSION_KEY} /v CurrentBuild"
            ),
        )

    def _behind_finding(
        self,
        ip: str,
        port: int,
        build: WindowsBuild,
        release: Release,
        verdict: tuple[Severity, int],
    ) -> FindingData:
        severity, gap = verdict
        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="Windows Cumulative Update Revision Behind",
            description=(
                f"This host runs {self._identity(build, release)}. Its update revision "
                f"(UBR {build.ubr}) is lower than {release.latest_ubr}, the newest "
                f"revision for this build recorded in ScanR's reference data as of "
                f"{REFERENCE_DATE.isoformat()} — a gap of {gap}.\n\n"
                "The UBR advances with each monthly cumulative update, so a host behind on "
                "it is missing every fix in the cumulative updates it has skipped. "
                "Cumulative means exactly that: the gap is not one vulnerability but all of "
                "them since the installed revision, including any that are being actively "
                "exploited.\n\n"
                "Read this as a lower bound rather than a precise measurement. ScanR's "
                f"reference revision is from {REFERENCE_DATE.isoformat()}, so the real gap "
                "is at least this large and probably larger. A host whose revision is at or "
                "above the reference is never reported, which means a recently-patched host "
                "cannot produce this finding from stale data — the error, if any, is always "
                "in the direction of silence."
            ),
            evidence=(
                f"Read over authenticated SMB from {ip}:{port}, registry key "
                f"HKLM\\{_CURRENT_VERSION_KEY}:\n"
                f"  CurrentBuild: {build.build}\n"
                f"  UBR: {build.ubr}\n"
                f"  Full version: {build.full_version}\n"
                f"  DisplayVersion: {build.display_version or '(not set)'}\n\n"
                f"Reference: {release.name} latest known UBR {release.latest_ubr} as of "
                f"{REFERENCE_DATE.isoformat()} (gap {gap})."
            ),
            remediation=(
                "Install the current cumulative update for this build and confirm the UBR "
                "advances. Then find out why the host fell behind, because a single "
                "installation does not fix a broken update path — the usual causes are a "
                "host that is off during the maintenance window, a WSUS or Configuration "
                "Manager client that has stopped reporting, insufficient free disk space "
                "for the servicing stack, or a paused update ring that was never resumed.\n\n"
                "Cross-check the host against the patch-management console: a system that "
                "the console reports as compliant while its registry says otherwise is a "
                "reporting failure, and that affects the whole estate's compliance figures, "
                "not just this host."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows/release-health/",
                "https://msrc.microsoft.com/update-guide",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"reg query \\\\{ip}\\HKLM\\{_CURRENT_VERSION_KEY} /v UBR"
            ),
        )
