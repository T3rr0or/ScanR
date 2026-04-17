"""ZeroLogon (CVE-2020-1472) detection.

ZeroLogon allows an unauthenticated attacker to set the machine account
password of a domain controller to empty, leading to full domain compromise.
Detection only — no exploitation attempt is made. The check sends crafted
Netlogon authentication packets and observes the response code; a vulnerable
DC returns STATUS_ACCESS_DENIED (0xC0000022) rather than a negotiation error,
because it accepted our zero-padded credential.

We use a safe, non-destructive detection probe that does NOT change any passwords.
"""
from __future__ import annotations

import asyncio
import logging
import os
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_DC_PORTS = (88, 389, 636)  # Kerberos + LDAP ports indicate DC


class ZerologonPlugin(PluginBase):
    id = "services.zerologon"
    name = "ZeroLogon (CVE-2020-1472)"
    description = "Detect domain controllers vulnerable to Netlogon privilege escalation (ZeroLogon)"
    category = PluginCategory.services
    severity = Severity.critical
    cve_ids = ["CVE-2020-1472"]
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    ports = [445]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        # Only check hosts that look like domain controllers
        host_port_nums = {p.number for p in host.ports if p.state == "open"}
        if not (host_port_nums & set(_DC_PORTS)):
            return []
        if 445 not in host_port_nums:
            return []

        # Get the DC's NetBIOS name (needed for the Netlogon call)
        dc_name = self._get_dc_name(host)
        if not dc_name:
            return []

        vulnerable = await asyncio.get_event_loop().run_in_executor(
            None, self._check_zerologon, host.ip, dc_name
        )
        if not vulnerable:
            return []

        return [FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="ZeroLogon Vulnerability Detected (CVE-2020-1472)",
            description=(
                "The domain controller is vulnerable to CVE-2020-1472 (ZeroLogon). "
                "An unauthenticated attacker on the network can exploit this vulnerability "
                "to reset the domain controller's machine account password to empty, "
                "then use impacket's secretsdump to extract all domain credentials, "
                "resulting in complete domain compromise."
            ),
            evidence=(
                f"Netlogon ServerAuthenticate3 on {host.ip} returned STATUS_ACCESS_DENIED "
                f"when supplied with all-zero client credentials, indicating the server "
                f"accepted the spoofed authenticator (DC name: {dc_name})."
            ),
            remediation=(
                "Apply Microsoft's August 2020 security update (KB4571694) and enable "
                "enforcement mode by setting FullSecureChannelProtection=1 in the registry. "
                "See MS guidance: https://support.microsoft.com/kb/4557222"
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
                "https://www.secura.com/blog/zero-logon",
                "https://support.microsoft.com/kb/4557222",
            ],
            port_number=445,
            protocol="tcp",
        )]

    def _get_dc_name(self, host: "Host") -> str | None:
        if host.hostname:
            return host.hostname.split(".")[0].upper()
        return None

    def _check_zerologon(self, ip: str, dc_name: str) -> bool:
        """Send a non-destructive ZeroLogon probe via impacket's Netlogon DCERPC."""
        try:
            from impacket.dcerpc.v5 import nrpc, transport
            from impacket.dcerpc.v5.dtypes import NULL
        except ImportError:
            logger.debug("impacket not available — skipping ZeroLogon check")
            return False

        try:
            binding = transport.DCERPCTransportFactory(f"ncacn_np:{ip}[\\pipe\\netlogon]")
            binding.set_connect_timeout(8)
            dce = binding.get_dce_rpc()
            dce.connect()
            dce.bind(nrpc.MSRPC_UUID_NRPC)

            # Non-destructive probe: call NetrServerReqChallenge then
            # NetrServerAuthenticate3 with all-zero credentials.
            # A patched DC rejects this immediately; a vulnerable DC returns
            # STATUS_ACCESS_DENIED (accepted authenticator but no session key).
            client_challenge = b"\x00" * 8
            resp = nrpc.hNetrServerReqChallenge(
                dce, NULL, dc_name + "\x00", client_challenge
            )
            server_challenge = resp["ServerChallenge"]

            zero_creds = b"\x00" * 8
            try:
                nrpc.hNetrServerAuthenticate3(
                    dce,
                    NULL,
                    dc_name + "$\x00",
                    nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                    dc_name + "\x00",
                    zero_creds,
                    0x212FFFFF,
                )
                # If we got here without exception, the server accepted zero creds
                dce.disconnect()
                return True
            except Exception as auth_exc:
                err = str(auth_exc)
                # STATUS_ACCESS_DENIED = server processed our fake creds (vulnerable)
                # STATUS_WRONG_PASSWORD / other = server rejected them (patched)
                dce.disconnect()
                return "STATUS_ACCESS_DENIED" in err or "0xC0000022" in err
        except Exception as exc:
            logger.debug("ZeroLogon probe failed for %s: %s", ip, exc)
            return False
