"""Active Directory password policy extraction via SMB/SAMR.

Extracts the domain password policy and flags settings that fall below
security best practices: short lockout duration, high lockout threshold,
short observation window.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# Recommended minimums
_MIN_LOCKOUT_DURATION_MINS = 30
_MIN_OBSERVATION_WINDOW_MINS = 30
_MAX_LOCKOUT_THRESHOLD = 5
_MIN_PASSWORD_LENGTH = 12


class AdPasswordPolicyPlugin(PluginBase):
    id = "services.ad_password_policy"
    name = "Weak Active Directory Password Policy"
    description = "Retrieve and evaluate the AD domain password policy via SMB/SAMR"
    category = PluginCategory.services
    severity = Severity.high
    requires_auth = True
    ports = [445]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 445 and p.state == "open" for p in host.ports):
            return []
        # Only run against hosts that look like domain controllers (ports 88, 389)
        host_ports = {p.number for p in host.ports}
        if not (88 in host_ports or 389 in host_ports):
            return []

        creds = context.credential("primary_domain") or context.credential_data
        if not creds or not creds.get("username"):
            return []

        policy = await asyncio.get_event_loop().run_in_executor(
            None,
            self._get_password_policy,
            host.ip,
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("domain", ""),
        )
        if policy is None:
            return []

        weak_settings = self._evaluate_policy(policy)
        if not weak_settings:
            return []

        evidence_lines = ["Domain password policy retrieved:"]
        for k, v in policy.items():
            evidence_lines.append(f"  {k}: {v}")
        evidence_lines.append("\nWeak settings identified:")
        for issue in weak_settings:
            evidence_lines.append(f"  - {issue}")

        return [FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="Weak Active Directory Password Policy",
            description=(
                "The Active Directory domain password policy contains settings that do not "
                "meet security best practices. Weak lockout thresholds allow attackers to "
                "perform brute-force or password spray attacks without triggering lockouts, "
                "while short lockout durations allow repeated attempts with minimal disruption."
            ),
            evidence="\n".join(evidence_lines),
            remediation=(
                f"Update the domain password policy to meet minimum standards:\n"
                f"  - Account Lockout Threshold: no higher than {_MAX_LOCKOUT_THRESHOLD}\n"
                f"  - Lockout Duration: at least {_MIN_LOCKOUT_DURATION_MINS} minutes\n"
                f"  - Lockout Observation Window: at least {_MIN_OBSERVATION_WINDOW_MINS} minutes\n"
                f"  - Minimum Password Length: at least {_MIN_PASSWORD_LENGTH} characters\n"
                "Configure via Group Policy: Computer Configuration > Windows Settings > "
                "Security Settings > Account Policies."
            ),
            references=[
                "https://blog.devolutions.net/2018/02/top-10-password-policies-and-best-practices-for-system-administrators",
                "https://www.microsoft.com/en-us/microsoft-365/blog/2018/03/05/azure-ad-and-adfs-best-practices-defending-against-password-spray-attacks/",
            ],
            port_number=445,
            protocol="tcp",
        )]

    def _get_password_policy(
        self, ip: str, username: str, password: str, domain: str
    ) -> dict | None:
        try:
            from impacket.dcerpc.v5 import samr, transport
        except ImportError:
            logger.debug("impacket not available — skipping AD password policy check")
            return None

        try:
            string_binding = f"ncacn_np:{ip}[\\pipe\\samr]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(username, password, domain)
            rpctransport.set_connect_timeout(8)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            if not domains:
                return None

            domain_name = domains[0]["Name"]
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            domain_sid = resp["DomainId"]

            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp["DomainHandle"]

            resp = samr.hSamrQueryInformationDomain(
                dce, domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
            )
            pwd_info = resp["Buffer"]["Password"]

            resp2 = samr.hSamrQueryInformationDomain(
                dce, domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
            )
            lockout = resp2["Buffer"]["Lockout"]

            # Convert 100-nanosecond intervals to minutes
            def to_mins(val: int) -> int:
                return abs(val) // 600_000_000

            policy = {
                "Minimum password length": pwd_info["MinPasswordLength"],
                "Password history length": pwd_info["PasswordHistoryLength"],
                "Account Lockout Threshold": lockout["LockoutThreshold"],
                "Lockout Duration (mins)": to_mins((lockout["LockoutDuration"].get("LowPart", 0) & 0xFFFFFFFF) | (lockout["LockoutDuration"].get("HighPart", 0) << 32)),
                "Lockout Observation Window (mins)": to_mins((lockout["LockoutObservationWindow"].get("LowPart", 0) & 0xFFFFFFFF) | (lockout["LockoutObservationWindow"].get("HighPart", 0) << 32)),
            }
            dce.disconnect()
            return policy
        except Exception as exc:
            logger.debug("Failed to retrieve AD password policy from %s: %s", ip, exc)
            return None

    def _evaluate_policy(self, policy: dict) -> list[str]:
        issues = []
        threshold = policy.get("Account Lockout Threshold", 0)
        if threshold == 0:
            issues.append("Account Lockout Threshold is 0 (disabled) — allows unlimited brute-force attempts")
        elif threshold > _MAX_LOCKOUT_THRESHOLD:
            issues.append(f"Account Lockout Threshold is {threshold} (recommended: ≤{_MAX_LOCKOUT_THRESHOLD})")

        duration = policy.get("Lockout Duration (mins)", 0)
        if 0 < duration < _MIN_LOCKOUT_DURATION_MINS:
            issues.append(f"Lockout Duration is {duration} min (recommended: ≥{_MIN_LOCKOUT_DURATION_MINS} min)")

        window = policy.get("Lockout Observation Window (mins)", 0)
        if 0 < window < _MIN_OBSERVATION_WINDOW_MINS:
            issues.append(f"Lockout Observation Window is {window} min (recommended: ≥{_MIN_OBSERVATION_WINDOW_MINS} min)")

        min_len = policy.get("Minimum password length", 0)
        if min_len < _MIN_PASSWORD_LENGTH:
            issues.append(f"Minimum password length is {min_len} (recommended: ≥{_MIN_PASSWORD_LENGTH})")

        return issues
