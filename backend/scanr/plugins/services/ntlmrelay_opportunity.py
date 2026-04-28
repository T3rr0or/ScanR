"""NTLM Relay chain opportunity detector.

Correlates two separately-found conditions across a scan:
  1. SMB signing disabled (services.smb_signing finding)
  2. Anonymous LDAP bind enabled (services.ldap_anon_bind finding)

When both exist in the same scan, an NTLM relay attack is feasible:
an attacker can relay SMB authentication to LDAP and perform privileged
operations (add computer to domain, modify ACLs, DCSync prep, etc.)

No network probes — pure cross-finding correlation via DB query.
Runs once per scan (scan-level cache guard).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy import select

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class NtlmRelayOpportunityPlugin(PluginBase):
    id = "services.ntlmrelay_opportunity"
    name = "NTLM Relay Chain Opportunity"
    description = "Detect when unsigned SMB + unauthenticated LDAP coexist in the same scan — enabling NTLM relay attacks"
    category = PluginCategory.services
    severity = Severity.high
    ports = [445, 389, 636]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        # Deduplicate — emit only once per scan
        _cache = "_ntlmrelay_checked"
        if getattr(context, _cache, False):
            return []
        setattr(context, _cache, True)

        try:
            from scanr.models import Finding
            smb_result = await context.db.execute(
                select(Finding.host_id, Finding.id).where(
                    Finding.scan_id == context.scan_id,
                    Finding.plugin_id == "services.smb_signing",
                )
            )
            smb_hosts = smb_result.all()

            ldap_result = await context.db.execute(
                select(Finding.host_id, Finding.id).where(
                    Finding.scan_id == context.scan_id,
                    Finding.plugin_id == "services.ldap_anon_bind",
                )
            )
            ldap_hosts = ldap_result.all()

            if not smb_hosts or not ldap_hosts:
                return []

            # Load host IPs for evidence
            from scanr.models import Host as HostModel
            smb_host_ids = {row.host_id for row in smb_hosts if row.host_id}
            ldap_host_ids = {row.host_id for row in ldap_hosts if row.host_id}

            smb_ips = []
            ldap_ips = []
            if smb_host_ids:
                h_result = await context.db.execute(
                    select(HostModel.ip).where(HostModel.id.in_(smb_host_ids))
                )
                smb_ips = [r[0] for r in h_result.all()]
            if ldap_host_ids:
                h_result = await context.db.execute(
                    select(HostModel.ip).where(HostModel.id.in_(ldap_host_ids))
                )
                ldap_ips = [r[0] for r in h_result.all()]

            evidence = (
                f"SMB signing disabled hosts ({len(smb_ips)}): {', '.join(smb_ips[:5])}\n"
                f"Anonymous LDAP bind hosts ({len(ldap_ips)}): {', '.join(ldap_ips[:5])}\n\n"
                "Attack chain:\n"
                "  1. Run Responder to capture NTLM authentication from victims\n"
                "  2. Relay captured NTLM auth to LDAP (ntlmrelayx.py -t ldap://dc_ip)\n"
                "  3. If relayed account has sufficient privileges:\n"
                "     - Add attacker-controlled computer account (shadow credentials)\n"
                "     - Modify ACLs to grant DCSync rights\n"
                "     - Dump domain credentials"
            )

            return [FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title=f"NTLM Relay Opportunity: {len(smb_ips)} unsigned SMB host(s) + {len(ldap_ips)} anonymous LDAP host(s)",
                description=(
                    f"This scan found {len(smb_ips)} host(s) with SMB signing disabled and "
                    f"{len(ldap_ips)} host(s) accepting anonymous LDAP binds. "
                    "Combined, these conditions enable NTLM relay attacks where an attacker intercepts "
                    "NTLM authentication (via Responder) and relays it to LDAP to perform privileged "
                    "operations without knowing any passwords."
                ),
                evidence=evidence,
                remediation=(
                    "1. Enable SMB signing on all hosts (Group Policy: 'Microsoft network server: Digitally sign communications always'). "
                    "2. Disable anonymous LDAP binds (set 'ldapServerIntegrity = 2' on domain controllers). "
                    "3. Enable LDAP channel binding (KB4520412). "
                    "4. Enable Extended Protection for Authentication (EPA) on all services. "
                    "5. Block LLMNR/NBT-NS to prevent credential capture (see services.llmnr_nbns_check)."
                ),
                references=[
                    "https://www.thehacker.recipes/ad/movement/ntlm/relay",
                    "https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py",
                ],
                protocol="tcp",
            )]

        except Exception as exc:
            logger.debug("NTLMRelay correlation failed: %s", exc)
        return []
