"""Windows host defence posture, read over authenticated SMB.

Several protections that a defender relies on can be turned off from the registry,
and when they are, the host is materially easier to attack in ways no
vulnerability scan would otherwise show:

* **SMBv1 enabled** — the protocol EternalBlue used. It has no legitimate role on
  a current network and its presence is both a direct exploit surface and a
  downgrade opportunity.
* **Microsoft Defender real-time protection disabled** — ``DisableRealtimeMonitoring``
  or ``DisableAntiSpyware`` set. Where no other EDR is present, malware simply
  runs.
* **PowerShell logging off** — without script-block and module logging, the single
  most-used post-exploitation toolset leaves almost no trace, so an intrusion is
  invisible to later investigation.
* **LSA protection / Credential Guard absent** — ``RunAsPPL`` unset and Credential
  Guard not running means LSASS can be read directly, which is how credentials are
  harvested after a foothold.

This is posture reporting: it lists what is missing so a defender can close the
gaps. Each item is confirmed from a specific registry value, and an absent value
is reported as "not enabled" only where the platform default is off.

Read-only: registry values only, no commands, RemoteRegistry never started.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
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

_SMB1_KEY = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
_DEFENDER_KEY = r"SOFTWARE\Microsoft\Windows Defender"
_DEFENDER_RTP_KEY = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
_DEFENDER_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows Defender"
_DEFENDER_POLICY_RTP_KEY = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
_PS_SCRIPTBLOCK_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
_PS_MODULE_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
_LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
_CG_KEY = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"
_PRODUCT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


@dataclass
class DefensePosture:
    smb1_enabled: bool = False
    defender_disabled: bool = False
    defender_present: bool = True
    ps_scriptblock_logging: bool = False
    ps_module_logging: bool = False
    lsa_ppl: bool = False
    credential_guard: bool = False
    is_server: bool = False
    product_name: str = ""
    read_ok: bool = False
    weaknesses: list[str] = field(default_factory=list)


class WindowsDefensesPlugin(PluginBase):
    id = "authenticated.windows_defenses"
    name = "Windows Defensive Posture"
    description = (
        "Report disabled host protections over authenticated SMB: SMBv1, Defender "
        "real-time protection, PowerShell logging, LSA protection and Credential Guard"
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

        posture = await self._read(host.ip, port, credential)
        if posture is None or not posture.read_ok:
            return []

        findings: list[FindingData] = []
        # SMBv1 is a remotely-reachable exploit surface, not just a posture gap, so
        # it is reported on its own with higher severity than the posture summary.
        if posture.smb1_enabled:
            findings.append(self._smb1_finding(host.ip, port, posture))
        summary = self._posture_finding(host.ip, port, posture)
        if summary is not None:
            findings.append(summary)
        return findings

    async def _read(self, ip: str, port: int, credential) -> DefensePosture | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._read_sync, ip, port, credential)

    @staticmethod
    def _read_sync(ip: str, port: int, credential) -> DefensePosture | None:
        reader = RegistryReader(ip=ip, credential=credential, port=port)
        if not reader.open():
            return None
        posture = DefensePosture()
        try:
            smb1 = reader.read_value(HKLM, _SMB1_KEY, "SMB1")
            # SMB1 absent means default; on current Windows the server feature is
            # off by default, so only an explicit 1 is reported.
            posture.smb1_enabled = bool(smb1 and smb1.as_int() == 1)

            posture.defender_disabled = WindowsDefensesPlugin._defender_off(reader)

            posture.ps_scriptblock_logging = WindowsDefensesPlugin._flag_on(
                reader, _PS_SCRIPTBLOCK_KEY, "EnableScriptBlockLogging"
            )
            posture.ps_module_logging = WindowsDefensesPlugin._flag_on(
                reader, _PS_MODULE_KEY, "EnableModuleLogging"
            )

            ppl = reader.read_value(HKLM, _LSA_KEY, "RunAsPPL")
            posture.lsa_ppl = bool(ppl and ppl.as_int() in (1, 2))
            cg = reader.read_value(HKLM, _CG_KEY, "Enabled")
            posture.credential_guard = bool(cg and cg.as_int() == 1)

            product = reader.read_values(
                HKLM, _PRODUCT_KEY, ("ProductName", "InstallationType")
            )
            if "ProductName" in product:
                posture.product_name = product["ProductName"].as_text()
            if "InstallationType" in product:
                posture.is_server = product["InstallationType"].as_text().lower() == "server"

            posture.read_ok = True
        except Exception as exc:  # noqa: BLE001
            logger.debug("defensive posture read partial on %s: %s", ip, exc)
        finally:
            reader.close()

        posture.weaknesses = WindowsDefensesPlugin._summarise(posture)
        return posture

    @staticmethod
    def _defender_off(reader: RegistryReader) -> bool:
        """True when Defender real-time protection is explicitly disabled."""
        for key in (_DEFENDER_POLICY_KEY, _DEFENDER_KEY):
            value = reader.read_value(HKLM, key, "DisableAntiSpyware")
            if value and value.as_int() == 1:
                return True
        for key in (_DEFENDER_POLICY_RTP_KEY, _DEFENDER_RTP_KEY):
            value = reader.read_value(HKLM, key, "DisableRealtimeMonitoring")
            if value and value.as_int() == 1:
                return True
        return False

    @staticmethod
    def _flag_on(reader: RegistryReader, key: str, name: str) -> bool:
        value = reader.read_value(HKLM, key, name)
        return bool(value and value.as_int() == 1)

    @staticmethod
    def _summarise(posture: DefensePosture) -> list[str]:
        weaknesses: list[str] = []
        if posture.defender_disabled:
            weaknesses.append("Microsoft Defender real-time protection is disabled")
        if not posture.ps_scriptblock_logging:
            weaknesses.append("PowerShell script-block logging is not enabled")
        if not posture.ps_module_logging:
            weaknesses.append("PowerShell module logging is not enabled")
        if not posture.lsa_ppl:
            weaknesses.append("LSA protection (RunAsPPL) is not enabled")
        if not posture.credential_guard:
            weaknesses.append("Credential Guard is not enabled")
        return weaknesses

    def _smb1_finding(
        self, ip: str, port: int, posture: DefensePosture
    ) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="SMBv1 Enabled",
            description=(
                f"The SMBv1 server protocol is enabled on this host "
                f"({posture.product_name or 'Windows'}).\n\n"
                "SMBv1 is the protocol EternalBlue (MS17-010) exploited, and it has no "
                "place on a current network: every supported Windows client and server "
                "speaks SMBv2/3, and SMBv1 is disabled by default on current builds, so its "
                "presence here is either a legacy setting or a deliberate re-enablement. "
                "Beyond the direct exploit surface, SMBv1 has no support for signing or the "
                "protections that make relay attacks harder, so it also weakens "
                "authentication for everything that still negotiates it.\n\n"
                "The usual reason it survives is one old device — a legacy scanner, a NAS, "
                "an industrial controller — that only speaks SMBv1. That is a reason to "
                "isolate the device, not to keep the protocol enabled estate-wide."
            ),
            evidence=(
                f"Read over authenticated SMB from {ip}:{port}:\n"
                f"  HKLM\\{_SMB1_KEY}\\SMB1 = 1"
            ),
            remediation=(
                "Disable the SMBv1 feature. On current Windows: "
                "'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' (or "
                "'Remove-WindowsFeature FS-SMB1' on a server), which removes both client "
                "and server. Confirm with 'Get-SmbServerConfiguration | select "
                "EnableSMB1Protocol'.\n\n"
                "Where a single legacy device requires SMBv1, do not keep it enabled "
                "everywhere for that device's sake: isolate the device on its own segment "
                "and enable SMBv1 only on the specific host that must talk to it, or replace "
                "the device. Audit SMBv1 usage first with 'Set-SmbServerConfiguration "
                "-AuditSmb1Access $true' so you can see what would actually break before "
                "removing it."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
                "https://attack.mitre.org/techniques/T1210/",
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"reg query \\\\{ip}\\HKLM\\{_SMB1_KEY} /v SMB1"
            ),
        )

    def _posture_finding(
        self, ip: str, port: int, posture: DefensePosture
    ) -> FindingData | None:
        if not posture.weaknesses:
            return None

        # Defender being off is a live gap; the rest are hardening and detection
        # measures whose absence is medium at most.
        severity = Severity.high if posture.defender_disabled else Severity.low

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=f"Windows Host Hardening Gaps ({len(posture.weaknesses)})",
            description=(
                f"Several host protections are not in place on this host "
                f"({posture.product_name or 'Windows'}). Individually these are hardening "
                "and detection settings rather than vulnerabilities, but together they "
                "describe how much room an attacker has once they reach the machine and how "
                "likely they are to be caught:\n\n"
                + "\n".join(f"  - {item}" for item in posture.weaknesses)
                + "\n\n"
                "The credential and logging items are the ones that decide the outcome of a "
                "foothold. Without LSA protection and Credential Guard, LSASS can be read to "
                "harvest the credentials of everyone logged on; without PowerShell logging, "
                "the activity that follows leaves little for an investigation to find; and "
                "with Defender's real-time protection off and no other EDR, there is nothing "
                "stopping the tooling from running in the first place."
                + (
                    "\n\nThis is a server, where an interactive administrator logon is more "
                    "likely, which makes the credential-protection gaps more valuable to an "
                    "attacker."
                    if posture.is_server
                    else ""
                )
            ),
            evidence=(
                f"Read over authenticated SMB from {ip}:{port}:\n"
                f"  Defender real-time protection: "
                f"{'DISABLED' if posture.defender_disabled else 'enabled or not overridden'}\n"
                f"  PowerShell script-block logging: "
                f"{'on' if posture.ps_scriptblock_logging else 'off'}\n"
                f"  PowerShell module logging: "
                f"{'on' if posture.ps_module_logging else 'off'}\n"
                f"  LSA protection (RunAsPPL): "
                f"{'on' if posture.lsa_ppl else 'off'}\n"
                f"  Credential Guard: "
                f"{'on' if posture.credential_guard else 'off'}"
            ),
            remediation=(
                "Close the gaps by policy so they apply across the estate, not just this "
                "host:\n\n"
                "- Re-enable Microsoft Defender real-time protection (or confirm a "
                "supported third-party EDR is present and active — this check only reads "
                "Defender). An 'off' state with no replacement is the item to fix first.\n"
                "- Enable PowerShell script-block logging and module logging via Group "
                "Policy (Administrative Templates → Windows Components → Windows PowerShell) "
                "and forward the events to your SIEM, so post-exploitation activity is "
                "recorded.\n"
                "- Enable LSA protection (RunAsPPL) to stop ordinary access to LSASS memory, "
                "and deploy Credential Guard on hardware that supports it to remove "
                "derived-credential theft entirely.\n\n"
                "Prioritise the credential-protection and logging settings on the hosts "
                "where administrators log on interactively — servers, jump hosts, "
                "management workstations — since those are where a stolen credential is "
                "worth the most."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/",
                "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
                "https://attack.mitre.org/techniques/T1562/001/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"reg query \\\\{ip}\\HKLM\\{_LSA_KEY} /v RunAsPPL"
            ),
        )
