"""Local Administrator Password Solution (LAPS) deployment check.

LAPS makes each machine's local administrator password unique and rotated,
managed centrally. Without it, organisations overwhelmingly ship one local
administrator password across a whole image, so recovering it on one host — for
example from an autologon value, a memory dump, or an offline SAM — gives local
administrator on every host built the same way. That single shared password is
what lets an attacker move laterally across an estate at will.

This check reads, read-only over SMB, whether either LAPS generation is
installed and active on the host:

* **Windows LAPS** (built into current Windows) — its policy and state live under
  ``SOFTWARE\\Microsoft\\Policies\\LAPS`` and ``...\\Windows\\LAPS\\State``.
* **Legacy Microsoft LAPS** (the older MSI, ``AdmPwd``) — indicated by
  ``AdmPwdEnabled`` and the presence of its client CSE.

Finding neither is the reportable condition, because it means local administrator
password reuse is the likely default. No password is ever read — LAPS passwords
are not in these keys, and this check does not go looking for them.

Read-only: a handful of registry values, no commands, RemoteRegistry never
started.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
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

# Windows LAPS (current)
_WINLAPS_POLICY = r"SOFTWARE\Microsoft\Policies\LAPS"
_WINLAPS_STATE = r"SOFTWARE\Microsoft\Windows\LAPS\State"
# Legacy Microsoft LAPS (AdmPwd)
_LEGACY_POLICY = r"SOFTWARE\Policies\Microsoft Services\AdmPwd"
# The domain-join / product marker helps say whether the host is even in scope.
_PRODUCT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_DOMAIN_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"


@dataclass
class LapsState:
    windows_laps_policy: bool = False
    windows_laps_active: bool = False
    legacy_laps_enabled: bool = False
    backup_directory: int | None = None
    product_name: str = ""
    domain: str = ""
    is_server: bool = False
    read_ok: bool = False

    @property
    def managed(self) -> bool:
        # Any positive signal of a working LAPS is enough to consider the host
        # covered. The policy alone is not — a policy set with no active state
        # means it was configured but is not managing this host.
        return self.windows_laps_active or self.legacy_laps_enabled or (
            self.windows_laps_policy and self.backup_directory in (1, 2)
        )


def backup_directory_name(value: int | None) -> str:
    return {
        0: "Disabled",
        1: "Azure AD / Entra ID",
        2: "Active Directory",
    }.get(value if value is not None else -1, "not configured")


class LapsStatusPlugin(PluginBase):
    id = "authenticated.laps_status"
    name = "LAPS Deployment Status"
    description = (
        "Check over authenticated SMB whether LAPS manages the local "
        "administrator password, whose absence implies password reuse across hosts"
    )
    category = PluginCategory.authenticated
    severity = Severity.medium
    requires_auth = True
    ports = [445]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        port = smb_port_open(host)
        if port is None:
            return []
        credential = windows_credential(context)
        if credential is None:
            return []

        state = await self._read(host.ip, port, credential)
        if state is None or not state.read_ok:
            return []
        if state.managed:
            # LAPS is doing its job; nothing to report.
            return []
        return [self._build_finding(host.ip, port, state)]

    async def _read(self, ip: str, port: int, credential) -> LapsState | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._read_sync, ip, port, credential)

    @staticmethod
    def _read_sync(ip: str, port: int, credential) -> LapsState | None:
        reader = RegistryReader(ip=ip, credential=credential, port=port)
        if not reader.open():
            return None
        state = LapsState()
        try:
            backup = reader.read_value(HKLM, _WINLAPS_POLICY, "BackupDirectory")
            if backup is not None:
                state.windows_laps_policy = True
                state.backup_directory = backup.as_int()

            last_update = reader.read_value(HKLM, _WINLAPS_STATE, "LastUpdateTime")
            password_expiry = reader.read_value(HKLM, _WINLAPS_STATE, "PasswordExpiryTime")
            state.windows_laps_active = bool(last_update or password_expiry)

            legacy = reader.read_value(HKLM, _LEGACY_POLICY, "AdmPwdEnabled")
            state.legacy_laps_enabled = bool(legacy and legacy.as_int() == 1)

            product = reader.read_values(
                HKLM, _PRODUCT_KEY, ("ProductName", "InstallationType")
            )
            if "ProductName" in product:
                state.product_name = product["ProductName"].as_text()
            if "InstallationType" in product:
                state.is_server = product["InstallationType"].as_text().lower() == "server"

            domain = reader.read_value(HKLM, _DOMAIN_KEY, "Domain")
            if domain is not None:
                state.domain = domain.as_text()

            state.read_ok = True
        except Exception as exc:  # noqa: BLE001
            logger.debug("LAPS state read partial on %s: %s", ip, exc)
            state.read_ok = state.read_ok or state.windows_laps_policy
        finally:
            reader.close()
        return state

    def _build_finding(self, ip: str, port: int, state: LapsState) -> FindingData:
        # A domain-joined host without LAPS is the real lateral-movement problem;
        # a standalone host's local password does not unlock the estate.
        domain_joined = bool(state.domain)
        severity = Severity.medium if domain_joined else Severity.low

        policy_note = ""
        if state.windows_laps_policy and not state.windows_laps_active:
            policy_note = (
                " A Windows LAPS policy is present (BackupDirectory = "
                f"{backup_directory_name(state.backup_directory)}), but the host shows no "
                "LAPS state, so the policy is configured yet not managing this machine — "
                "the password has not been backed up or rotated. That is worth checking "
                "as a deployment failure rather than a clean absence."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="Local Administrator Password Not Managed by LAPS",
            description=(
                f"Neither Windows LAPS nor the legacy Microsoft LAPS is actively managing "
                f"the local administrator password on this host.{policy_note}\n\n"
                "Without LAPS, the built-in local administrator password is almost always "
                "set once by the build image and left unchanged, which means it is the "
                "same on every host built from that image. An attacker who recovers it on "
                "one machine — and the local administrator hash is recoverable from any "
                "host where they reach SYSTEM — can then authenticate to every other host "
                "that shares it, using pass-the-hash where the plaintext is not known. "
                "That is the mechanism behind most rapid internal spread: one foothold "
                "becomes administrator on hundreds of machines without any further "
                "vulnerability.\n\n"
                + (
                    "This host is domain-joined, so it is part of exactly the population "
                    "where shared local credentials enable lateral movement across the "
                    "domain."
                    if domain_joined
                    else "This host does not appear to be domain-joined. The risk of a "
                    "shared local password is lower for a standalone machine, but it still "
                    "applies if this host was built from the same image as others."
                )
                + "\n\nLAPS closes this by giving each machine a unique, automatically "
                "rotated local administrator password held in Active Directory or Entra ID, "
                "so recovering one host's password grants access to that one host only."
            ),
            evidence=(
                f"Read over authenticated SMB from {ip}:{port}:\n"
                f"  Windows LAPS policy (HKLM\\{_WINLAPS_POLICY}\\BackupDirectory): "
                f"{backup_directory_name(state.backup_directory) if state.windows_laps_policy else 'absent'}\n"
                f"  Windows LAPS state (HKLM\\{_WINLAPS_STATE}): "
                f"{'present' if state.windows_laps_active else 'absent'}\n"
                f"  Legacy LAPS (AdmPwdEnabled): "
                f"{'enabled' if state.legacy_laps_enabled else 'absent'}\n"
                f"  ProductName: {state.product_name or '(not read)'}\n"
                f"  Domain: {state.domain or '(none / workgroup)'}"
            ),
            remediation=(
                "Deploy Windows LAPS, which is built into current Windows and needs no "
                "separate agent. Configure it by policy with 'BackupDirectory' set to "
                "Active Directory (2) or Entra ID (1), a rotation interval, and password "
                "complexity, then confirm hosts are backing up and rotating — a policy with "
                "no resulting state (the case flagged above, where it applies) manages "
                "nothing.\n\n"
                "Roll it across the whole estate, not just the servers: workstations are "
                "where lateral movement usually begins, and they are the larger population. "
                "Restrict who can read the LAPS password attribute in AD to the specific "
                "administrative groups that need it, since read access to it is itself local "
                "administrator on the target.\n\n"
                "Rotate the existing shared local administrator password as part of the "
                "rollout — LAPS taking over does not change a password that has already been "
                "reused across the fleet and may already be known. Consider also disabling "
                "the built-in Administrator account where a per-host managed account can "
                "replace it."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
                "https://attack.mitre.org/techniques/T1078/003/",
                "https://attack.mitre.org/techniques/T1550/002/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"reg query \\\\{ip}\\HKLM\\{_WINLAPS_STATE}   # no state = not managed"
            ),
        )
