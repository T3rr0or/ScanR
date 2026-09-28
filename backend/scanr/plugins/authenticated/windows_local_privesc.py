"""Local privilege escalation misconfigurations on Windows, read from the registry.

Four classic paths from "a user on this machine" to SYSTEM or to another user's
credentials. All four are configuration, not vulnerabilities, so no patch closes
them and they survive every update cycle until someone changes the setting:

* **AlwaysInstallElevated** — MSI packages install as SYSTEM regardless of who
  runs them. Any user builds an MSI that adds an administrator and runs it. This
  is the most direct local escalation Windows offers and it exists only because
  someone set two policy values.
* **Autologon credentials** — ``DefaultPassword`` under Winlogon stores a password
  in cleartext in a registry key every authenticated user can read. The account is
  typically a local administrator, and often the same one across a fleet.
* **WDigest ``UseLogonCredential``** — re-enables cleartext password caching in
  LSASS, which Microsoft disabled by default in 2014. It converts any SYSTEM-level
  foothold into every interactively logged-on user's plaintext password.
* **Unquoted service paths** — a service whose ``ImagePath`` contains spaces and no
  quotes makes Windows try each truncation in turn, so a writable directory
  earlier in the path lets a user place a binary that runs as the service account.

Strictly read-only: registry values and service subkey names. No commands run, and
the RemoteRegistry service is never started.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.authenticated._windows import (
    HKLM,
    HKU,
    RegistryReader,
    smb_port_open,
    windows_credential,
)

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_INSTALLER_KEY = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
_WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_WDIGEST_KEY = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"

_MAX_SERVICES = 800
_MAX_SERVICES_REPORTED = 20
# A per-user hive is only a real user's when the SID looks like one; the machine
# and service SIDs are not interesting here.
_USER_SID_RE = re.compile(r"^S-1-5-21-[\d-]+$")

# Directories where a non-administrator cannot normally write, so a truncation
# landing there is not exploitable. Deliberately conservative: anything outside
# these is treated as potentially writable and reported.
_PROTECTED_PREFIXES = (
    r"c:\windows",
    r"%systemroot%",
    r"\systemroot",
    r"\??\c:\windows",
)

_EXECUTABLE_RE = re.compile(r"^(.*?\.(?:exe|com|bat|cmd|scr))(\s|$)", re.I)


@dataclass
class UnquotedService:
    name: str
    image_path: str
    truncations: list[str] = field(default_factory=list)


@dataclass
class PrivescFindings:
    """Everything the registry said, gathered in one session."""

    installer_elevated_machine: bool = False
    installer_elevated_users: list[str] = field(default_factory=list)
    autologon_user: str = ""
    autologon_domain: str = ""
    autologon_password_present: bool = False
    autologon_enabled: bool = False
    wdigest_cleartext: bool = False
    unquoted_services: list[UnquotedService] = field(default_factory=list)
    services_examined: int = 0

    @property
    def anything_found(self) -> bool:
        return bool(
            self.installer_elevated_machine
            or self.autologon_password_present
            or self.wdigest_cleartext
            or self.unquoted_services
        )


def truncations(image_path: str) -> list[str]:
    """The paths Windows tries in turn for an unquoted ImagePath.

    Windows splits on each space and appends ``.exe``, so
    ``C:\\Program Files\\App\\svc.exe`` is attempted as ``C:\\Program.exe`` first.
    """
    match = _EXECUTABLE_RE.match(image_path.strip())
    executable = match.group(1) if match else image_path.strip().split(" ")[0]
    parts = executable.split(" ")
    candidates: list[str] = []
    accumulated = ""
    for part in parts[:-1]:
        accumulated = f"{accumulated} {part}".strip() if accumulated else part
        candidates.append(f"{accumulated}.exe")
    return candidates


def is_unquoted_vulnerable(image_path: str) -> bool:
    """True when an unquoted ImagePath can be hijacked by an earlier truncation.

    Requires all of: no leading quote, a space inside the executable path itself
    (not merely in its arguments), and at least one truncation that does not land
    inside a directory only administrators can write.
    """
    path = (image_path or "").strip()
    if not path or path.startswith('"'):
        return False
    # A driver registered by NT path is not launched through this code path.
    if path.lower().startswith(("\\systemroot\\system32\\drivers", "system32\\drivers")):
        return False

    match = _EXECUTABLE_RE.match(path)
    if match is None:
        # No recognisable executable, so no truncation behaviour to reason about.
        return False
    executable = match.group(1)
    if " " not in executable:
        return False

    lowered = executable.lower()
    if lowered.startswith(_PROTECTED_PREFIXES):
        return False
    return bool(truncations(path))


class WindowsLocalPrivescPlugin(PluginBase):
    id = "authenticated.windows_local_privesc"
    name = "Windows Local Privilege Escalation Misconfiguration"
    description = (
        "Detect AlwaysInstallElevated, cleartext autologon credentials, WDigest "
        "cleartext caching and unquoted service paths over authenticated SMB"
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

        gathered = await self._gather(host.ip, port, credential)
        if gathered is None or not gathered.anything_found:
            return []

        findings: list[FindingData] = []
        if gathered.installer_elevated_machine:
            findings.append(self._installer_finding(host.ip, port, gathered))
        if gathered.autologon_password_present:
            findings.append(self._autologon_finding(host.ip, port, gathered))
        if gathered.wdigest_cleartext:
            findings.append(self._wdigest_finding(host.ip, port))
        if gathered.unquoted_services:
            findings.append(self._unquoted_finding(host.ip, port, gathered))
        return findings

    async def _gather(self, ip: str, port: int, credential) -> PrivescFindings | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._gather_sync, ip, port, credential)

    @staticmethod
    def _gather_sync(ip: str, port: int, credential) -> PrivescFindings | None:
        reader = RegistryReader(ip=ip, credential=credential, port=port)
        if not reader.open():
            return None
        result = PrivescFindings()
        try:
            machine = reader.read_value(HKLM, _INSTALLER_KEY, "AlwaysInstallElevated")
            result.installer_elevated_machine = bool(machine and machine.as_int() == 1)
            if result.installer_elevated_machine:
                # The escalation needs the per-user value too, so the loaded user
                # hives are checked to say whether it is actually reachable.
                for sid in reader.enum_subkeys(HKU, "", limit=50):
                    if not _USER_SID_RE.match(sid):
                        continue
                    per_user = reader.read_value(
                        HKU, f"{sid}\\{_INSTALLER_KEY}", "AlwaysInstallElevated"
                    )
                    if per_user and per_user.as_int() == 1:
                        result.installer_elevated_users.append(sid)

            winlogon = reader.read_values(
                HKLM,
                _WINLOGON_KEY,
                ("AutoAdminLogon", "DefaultUserName", "DefaultDomainName", "DefaultPassword"),
            )
            autologon = winlogon.get("AutoAdminLogon")
            result.autologon_enabled = bool(autologon and autologon.as_text().strip() in ("1", "true"))
            password = winlogon.get("DefaultPassword")
            # The value's presence is what matters; the password itself is never
            # recorded in a finding.
            result.autologon_password_present = bool(password and password.as_text().strip())
            if "DefaultUserName" in winlogon:
                result.autologon_user = winlogon["DefaultUserName"].as_text()
            if "DefaultDomainName" in winlogon:
                result.autologon_domain = winlogon["DefaultDomainName"].as_text()

            wdigest = reader.read_value(HKLM, _WDIGEST_KEY, "UseLogonCredential")
            result.wdigest_cleartext = bool(wdigest and wdigest.as_int() == 1)

            for name in reader.enum_subkeys(HKLM, _SERVICES_KEY, limit=_MAX_SERVICES):
                image = reader.read_value(HKLM, f"{_SERVICES_KEY}\\{name}", "ImagePath")
                if image is None:
                    continue
                result.services_examined += 1
                path = image.as_text()
                if is_unquoted_vulnerable(path):
                    result.unquoted_services.append(
                        UnquotedService(
                            name=name, image_path=path, truncations=truncations(path)
                        )
                    )
        except Exception as exc:  # noqa: BLE001 - a partial read is still useful
            logger.debug("windows privesc gather partial on %s: %s", ip, exc)
        finally:
            reader.close()
        return result

    def _installer_finding(
        self, ip: str, port: int, gathered: PrivescFindings
    ) -> FindingData:
        # Both halves set means any user can escalate today; the machine half
        # alone means the policy is staged and one user-side value away.
        reachable = bool(gathered.installer_elevated_users)
        severity = Severity.critical if reachable else Severity.high

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="AlwaysInstallElevated Enabled — Any User Can Install as SYSTEM",
            description=(
                "The AlwaysInstallElevated policy is enabled on this host. Windows "
                "Installer packages run with SYSTEM privileges regardless of who starts "
                "them.\n\n"
                "This is a complete local privilege escalation requiring no exploit and no "
                "vulnerability. Any user who can log on builds an MSI whose install action "
                "adds them to the local Administrators group — or starts a shell — and runs "
                "it with 'msiexec /quiet /i payload.msi'. The tooling to generate that MSI "
                "is a single msfvenom command.\n\n"
                + (
                    "Both the machine and per-user halves of the policy are set, so the "
                    "escalation is available right now to the user hives listed in the "
                    "evidence."
                    if reachable
                    else "Only the machine half (HKLM) is set. Windows requires the matching "
                    "per-user value, so the escalation is not currently reachable on the "
                    "user hives that were loaded when this host was read — but the policy "
                    "is usually deployed by Group Policy to both, and any hive that has not "
                    "logged on yet may receive it. Treat this as the setting being wrong "
                    "rather than as safe."
                )
                + "\n\nThe policy exists so that unprivileged users can install specific "
                "approved software. It cannot be scoped to particular packages, which is why "
                "it is effectively never the right answer."
            ),
            evidence=(
                f"Read over authenticated SMB from {ip}:{port}:\n"
                f"  HKLM\\{_INSTALLER_KEY}\\AlwaysInstallElevated = 1\n"
                + (
                    "".join(
                        f"  HKU\\{sid}\\{_INSTALLER_KEY}\\AlwaysInstallElevated = 1\n"
                        for sid in gathered.installer_elevated_users
                    )
                    if gathered.installer_elevated_users
                    else "  No loaded user hive has the matching per-user value set.\n"
                )
            ),
            remediation=(
                "Set both values to 0, or delete them, at the policy level so they cannot "
                "be reapplied: Computer Configuration → Administrative Templates → Windows "
                "Components → Windows Installer → 'Always install with elevated privileges' "
                "= Disabled, and the same under User Configuration. Setting only one half "
                "leaves the policy staged.\n\n"
                "Find out which Group Policy object set it and fix it there — a local "
                "registry change is reverted at the next policy refresh.\n\n"
                "Where unprivileged users genuinely need to install specific software, "
                "deploy it through Configuration Manager, Intune or a per-package elevation "
                "tool instead. Those grant the specific installation rather than a blanket "
                "right to run any installer as SYSTEM."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated",
                "https://attack.mitre.org/techniques/T1548/002/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"reg query \\\\{ip}\\HKLM\\{_INSTALLER_KEY} /v AlwaysInstallElevated"
            ),
        )

    def _autologon_finding(
        self, ip: str, port: int, gathered: PrivescFindings
    ) -> FindingData:
        account = gathered.autologon_user or "(not set)"
        if gathered.autologon_domain:
            account = f"{gathered.autologon_domain}\\{account}"

        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="Autologon Password Stored in Cleartext in the Registry",
            description=(
                f"This host stores an autologon password in cleartext under the Winlogon "
                f"registry key, for the account {account}.\n\n"
                "Any authenticated user on the host can read that value — the key's default "
                "permissions grant read access to Users, and no privilege is needed. The "
                "account configured for autologon is typically a local administrator, so "
                "this is a plaintext administrator password available to every user of the "
                "machine.\n\n"
                "The impact rarely stops at one host. Autologon is usually configured by an "
                "image or a build script, so the same credential is present across every "
                "machine built the same way — a single read gives administrator access to "
                "the whole group. Where the account is a domain account, it is credential "
                "access to the domain from an unprivileged local session.\n\n"
                "Retrieving it needs no tooling: 'reg query' is enough, and every "
                "post-exploitation framework checks this key automatically. ScanR confirmed "
                "the value is present and populated but has deliberately not recorded it."
            ),
            evidence=(
                f"Read over authenticated SMB from {ip}:{port}, registry key "
                f"HKLM\\{_WINLOGON_KEY}:\n"
                f"  AutoAdminLogon = {'1' if gathered.autologon_enabled else '(set but not 1)'}\n"
                f"  DefaultUserName = {gathered.autologon_user or '(not set)'}\n"
                f"  DefaultDomainName = {gathered.autologon_domain or '(not set)'}\n"
                "  DefaultPassword = present and non-empty "
                "(value deliberately not recorded in this report)"
            ),
            remediation=(
                "Delete the DefaultPassword value, and treat the credential as compromised: "
                "rotate it now, and everywhere else it is used. It has been readable by "
                "every user of this host for as long as it has been set, so rotation is not "
                "optional even if the host looks untouched.\n\n"
                "If autologon is genuinely required — a kiosk, a shop-floor terminal, a "
                "digital sign — use Sysinternals Autologon, which stores the password in the "
                "LSA secret store rather than a user-readable registry value. That is "
                "obscured rather than protected (a SYSTEM-level compromise still recovers "
                "it), so pair it with an account that has no rights beyond running that one "
                "application, no local administrator membership, and no ability to log on "
                "anywhere else.\n\n"
                "Then check the rest of the estate for the same value. Autologon almost "
                "always arrives from a shared image or deployment script, so one host with "
                "this setting usually means a group of them and one shared password."
            ),
            references=[
                "https://learn.microsoft.com/en-us/sysinternals/downloads/autologon",
                "https://attack.mitre.org/techniques/T1552/002/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"reg query \\\\{ip}\\HKLM\\{_WINLOGON_KEY} /v DefaultPassword"
            ),
        )

    def _wdigest_finding(self, ip: str, port: int) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="WDigest Cleartext Credential Caching Re-Enabled",
            description=(
                "UseLogonCredential is set to 1, which re-enables WDigest cleartext "
                "credential caching. LSASS now keeps the plaintext password of every "
                "interactively logged-on user in memory.\n\n"
                "Microsoft disabled this by default in 2014 precisely because it turns any "
                "SYSTEM-level foothold into plaintext passwords. With it on, an attacker who "
                "reaches SYSTEM on this host does not need to crack a hash or relay an "
                "authentication — they read the passwords directly, and a password works "
                "everywhere the account is valid, including services that never accept a "
                "hash.\n\n"
                "The account that matters most here is whichever administrator last logged "
                "on to this host. If a domain administrator has ever had an interactive "
                "session on it, their plaintext password has been sitting in this machine's "
                "memory.\n\n"
                "This setting does not appear by accident. It is usually added to make an "
                "old application or a monitoring agent work, and then never removed."
            ),
            evidence=(
                f"Read over authenticated SMB from {ip}:{port}:\n"
                f"  HKLM\\{_WDIGEST_KEY}\\UseLogonCredential = 1\n\n"
                "The default on all supported Windows versions is for this value to be "
                "absent or 0."
            ),
            remediation=(
                "Set UseLogonCredential to 0 or delete the value, then reboot — existing "
                "sessions keep their cached plaintext until the host restarts, so the change "
                "is not effective immediately.\n\n"
                "Find whatever set it. If an application required WDigest, replace or "
                "reconfigure that application rather than restoring the setting; nothing "
                "supported has needed WDigest for a decade.\n\n"
                "Rotate the passwords of accounts that have logged on to this host "
                "interactively while the setting was active, starting with any "
                "administrative account. Then reduce the exposure structurally: enable LSA "
                "protection (RunAsPPL) and Credential Guard, and stop administrators logging "
                "on interactively to ordinary hosts — use a privileged access workstation and "
                "restricted-admin RDP, so an administrator's credential is never resident on "
                "a machine like this one."
            ),
            references=[
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/credentials-protection-management",
                "https://attack.mitre.org/techniques/T1003/001/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"reg query \\\\{ip}\\HKLM\\{_WDIGEST_KEY} /v UseLogonCredential"
            ),
        )

    def _unquoted_finding(
        self, ip: str, port: int, gathered: PrivescFindings
    ) -> FindingData:
        services = gathered.unquoted_services
        lines: list[str] = []
        for service in services[:_MAX_SERVICES_REPORTED]:
            lines.append(f"  {service.name}")
            lines.append(f"    ImagePath: {service.image_path}")
            lines.append(
                f"    Windows would try: {', '.join(service.truncations[:4])}"
            )
        if len(services) > _MAX_SERVICES_REPORTED:
            lines.append(f"  [... {len(services) - _MAX_SERVICES_REPORTED} more]")

        return FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title=f"{len(services)} Service(s) With Unquoted Executable Paths",
            description=(
                f"{len(services)} service(s) on this host have an ImagePath that contains "
                "spaces and is not quoted. Windows resolves such a path by trying each "
                "truncation in turn, appending '.exe' — so for "
                "'C:\\Program Files\\App\\svc.exe' it attempts 'C:\\Program.exe' first.\n\n"
                "If a user can create a file at one of those earlier paths, that file runs "
                "as the service's account — usually SYSTEM — every time the service starts. "
                "The escalation is then just waiting for a reboot, and a user who can "
                "restart the service does not even wait.\n\n"
                "Whether this is exploitable depends on the filesystem permissions of the "
                "directories involved, which this check cannot read remotely. The common "
                "cases are a service installed into a directory the vendor created with "
                "permissive ACLs, or a path under a non-standard root such as 'C:\\Apps' "
                "that inherits the permissive default of a drive root. Services under "
                "C:\\Windows are excluded here, since those directories are not "
                "user-writable.\n\n"
                "Verify the ACLs before treating any single entry as exploitable — but fix "
                "the quoting regardless, since it costs nothing and removes the class."
            ),
            evidence=(
                f"Read over authenticated SMB from {ip}:{port}, enumerated "
                f"{gathered.services_examined} service(s) under HKLM\\{_SERVICES_KEY}.\n"
                f"Unquoted paths with spaces outside protected directories:\n"
                + "\n".join(lines)
            ),
            remediation=(
                "Quote the ImagePath of each service listed: "
                "'sc config <name> binPath= \"\\\"C:\\Program Files\\App\\svc.exe\\\" -args\"'. "
                "Report the defect to the vendor where a third-party installer created it, "
                "since a reinstall or upgrade will reintroduce it.\n\n"
                "Then check the directory ACLs on the truncation paths — that is what "
                "decides exploitability. 'icacls' on each parent directory: no non-"
                "administrative principal (Users, Authenticated Users, Everyone) should have "
                "write, create-files or modify rights. Fixing a permissive ACL also closes "
                "the related unquoted-path and DLL-hijacking issues in the same directory.\n\n"
                "Install applications under 'C:\\Program Files' rather than a custom root: "
                "that directory's default ACL denies user writes, whereas a directory created "
                "at the root of a drive inherits permissions that allow them."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1574/009/",
                "https://learn.microsoft.com/en-us/windows/win32/services/service-record-list",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                "wmic service get name,pathname,startmode | findstr /i /v \"C:\\\\Windows\\\\\" | findstr /i /v \"\\\"\""
            ),
        )
