"""LDAP channel binding and LDAP signing enforcement check.

On Windows domains, LDAP channel binding + signing is the #1 Active Directory
hardening control against NTLM relay attacks. This plugin checks whether the
domain controller enforces these settings.

References:
  - ADV190023 / CVE-2020-1472 mitigation guidance
  - MS-ADTS §3.1.1.3.4.1.15 (LDAP Server Policy)
"""
from __future__ import annotations

import asyncio
import logging
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

LDAP_PORTS = [389, 636, 3268, 3269]

# LDAP extended operation OID for getting server policy
LDAP_SERVER_POLICY_OID = "1.2.840.113556.1.4.2254"  # LdapPolicyOperation


class LdapSigningPlugin(PluginBase):
    id = "services.ldap_signing"
    name = "LDAP Signing / Channel Binding Check"
    description = (
        "Check if domain controllers enforce LDAP signing and channel binding "
        "— the primary defense against NTLM relay attacks"
    )
    category = PluginCategory.services
    severity = Severity.high
    ports = LDAP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in (LDAP_PORTS if self.ports is None else self.ports):
                continue
            result = await self._check_ldap(host.ip, port.number)
            if result:
                findings.append(result)
        return findings

    async def _check_ldap(self, ip: str, port: int) -> FindingData | None:
        """Probe LDAP server via raw TCP to detect signing requirements."""
        import socket
        import ssl

        try:
            # Build a minimal LDAP search request (no bind — anonymous probe)
            # This is a simplified check: we connect and test whether an
            # unsigned simple bind is rejected.
            signing_required = await self._test_simple_bind(ip, port)
            channel_binding = await self._test_channel_binding(ip, port)

            if signing_required is None:
                return None  # couldn't connect

            issues: list[str] = []
            severity = Severity.low

            if not signing_required:
                issues.append(
                    "LDAP signing is NOT required. An attacker can perform "
                    "NTLM relay attacks against this domain controller."
                )
                severity = Severity.high
            else:
                issues.append("LDAP signing is enforced.")

            if channel_binding is False:
                issues.append(
                    "LDAP channel binding is NOT enforced. EPA/TLS channel "
                    "binding would add an additional layer of relay protection."
                )
                if severity != Severity.high:
                    severity = Severity.medium

            if severity == Severity.low:
                return None  # all good

            return FindingData(
                plugin_id=self.id,
                severity=severity,
                title="LDAP Signing / Channel Binding Weakness",
                description="\n".join(issues),
                evidence=(
                    f"Host: {ip}:{port}\n"
                    f"LDAP signing required: {signing_required}\n"
                    f"Channel binding enforced: {channel_binding}\n"
                ),
                remediation=(
                    "Configure Domain Controller: LDAP Server Signing Requirements "
                    "to 'Require signing' via GPO. Enable LDAP channel binding "
                    "(set LdapEnforceChannelBinding to 2).\n"
                    "GPO path: Computer Configuration > Policies > Windows Settings > "
                    "Security Settings > Local Policies > Security Options > "
                    "\"Domain controller: LDAP server signing requirements\"\n"
                    "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\"
                    "LdapEnforceChannelBinding = 2"
                ),
                references=[
                    "https://support.microsoft.com/en-us/topic/use-the-ldapenforcechannelbinding-registry-entry-to-make-ldap-authentication-over-ssl-tls-more-secure-e9ee2e0a-7c3d-4bed-9c7c-86e1c1d3c60",
                    "https://learn.microsoft.com/en-us/windows-server/security/ldap/ldap-signing-and-channel-binding",
                    "https://attack.mitre.org/techniques/T1557/001/",
                ],
                port_number=port,
                protocol="tcp",
            )
        except Exception as exc:
            logger.debug("LDAP signing check failed for %s:%s: %s", ip, port, exc)
            return None

    async def _test_simple_bind(self, ip: str, port: int) -> bool | None:
        """Attempt unsigned simple bind. Returns True if signing is required (bind rejected)."""
        try:
            import socket
            reader, writer = await asyncio.open_connection(ip, port)
            try:
                # LDAP simple bind with null DN (anonymous fails if signing required)
                # MS AD returns resultCode=8 (strongerAuthRequired) when signing enforced
                # on simple binds over non-TLS connections on port 389.
                msg_id = 1
                dn = b""  # anonymous
                password = b""

                bind_request = self._build_ldap_bind(msg_id, dn, password)
                writer.write(bind_request)
                await writer.drain()

                response = await asyncio.wait_for(reader.read(4096), timeout=5.0)

                if len(response) < 2:
                    return None

                # Parse LDAP result code
                result_code = self._parse_ldap_result(response)
                if result_code is None:
                    return None

                # resultCode == 8 means strongerAuthRequired (signing enforced)
                # resultCode == 0 means success (signing not required)
                # resultCode == 49 means invalidCredentials (signing likely not required)
                if result_code == 8:
                    return True  # signing required
                return False  # anonymous bind succeeded or invalid creds → no signing
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            return None

    async def _test_channel_binding(self, ip: str, port: int) -> bool | None:
        """Check if channel binding is enforced.
        
        We can't fully test this without a valid TLS session + token,
        but we check if LDAPS (636) or StartTLS is available and test
        the server's policy response via rootDSE attributes.
        """
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            try:
                # Query rootDSE for supported capabilities
                search_request = self._build_rootdse_search(msg_id=1)
                writer.write(search_request)
                await writer.drain()

                response = await asyncio.wait_for(reader.read(8192), timeout=5.0)

                # Check for supportedCapabilities in the response
                # Channel binding support indicated by OID 1.3.6.1.4.1.311.25
                resp_str = response.decode("latin-1", errors="replace")
                if "1.3.6.1.4.1.311.25" in resp_str:
                    return True  # channel binding capability present
                # Can't definitively determine → report as unknown
                return None
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            return None

    @staticmethod
    def _build_ldap_bind(msg_id: int, dn: bytes, password: bytes) -> bytes:
        """Build minimal LDAP simple bind request (BER-encoded)."""
        import struct

        # LDAPMessage ::= SEQUENCE { messageID, protocolOp }
        # BindRequest ::= [APPLICATION 0] SEQUENCE { version, name, authentication }
        bind_body = (
            b"\x02\x01\x03"  # version = 3 (LDAPv3)
            + b"\x04" + struct.pack("B", len(dn)) + dn  # name
            + b"\x80" + struct.pack("B", len(password)) + password  # simple auth
        )
        bind_body_len = len(bind_body)
        bind_pdu = b"\x60" + LdapSigningPlugin._encode_length(bind_body_len) + bind_body

        full_len = len(bind_pdu) + 4
        msg = (
            b"\x30" + LdapSigningPlugin._encode_length(full_len - 2)
            + b"\x02\x01" + struct.pack("B", msg_id)
            + bind_pdu
        )
        return msg

    @staticmethod
    def _build_rootdse_search(msg_id: int) -> bytes:
        """Build LDAP search for rootDSE attributes."""
        import struct

        # SearchRequest baseObject scope, null base DN, present filter
        base = b""
        search_body = (
            base + b"\x00"  # base DN (null → rootDSE)
            + b"\x0a\x01\x00"  # scope = baseObject
            + b"\x0a\x01\x00"  # derefAliases = neverDerefAliases
            + b"\x02\x01\x00"  # sizeLimit = 0
            + b"\x02\x01\x00"  # timeLimit = 0
            + b"\x01\x01\x00"  # typesOnly = False
            + b"\x87\x0bobjectClass"  # filter: (objectClass=*)
        )
        # Attributes: supportedLDAPVersion, supportedCapabilities
        attrs = b"\x04\x14supportedLDAPVersion\x04\x15supportedCapabilities"
        attr_seq = b"\x30" + LdapSigningPlugin._encode_length(len(attrs)) + attrs
        search_body += attr_seq
        search_pdu = b"\x63" + LdapSigningPlugin._encode_length(len(search_body)) + search_body
        full_len = len(search_pdu) + 4
        msg = (
            b"\x30" + LdapSigningPlugin._encode_length(full_len - 2)
            + b"\x02\x01" + struct.pack("B", msg_id)
            + search_pdu
        )
        return msg

    @staticmethod
    def _encode_length(n: int) -> bytes:
        if n < 128:
            return struct.pack("B", n)
        # Long form
        enc = b""
        while n > 0:
            enc = struct.pack("B", n & 0xFF) + enc
            n >>= 8
        return struct.pack("B", 0x80 | len(enc)) + enc

    @staticmethod
    def _parse_ldap_result(data: bytes) -> int | None:
        """Parse resultCode from LDAP response PDU."""
        try:
            # Skip SEQUENCE header + messageID
            if len(data) < 4 or data[0] != 0x30:
                return None
            seq_len = data[1]
            if seq_len & 0x80:
                # long-form length
                num_len_bytes = seq_len & 0x7F
                offset = 2 + num_len_bytes
            else:
                offset = 2
            # Skip messageID (INTEGER tag + length + value)
            if data[offset] != 0x02:
                return None
            offset += 2 + data[offset + 1]

            # ProtocolOp: should be bindResponse [APPLICATION 1]
            if data[offset] == 0x61:
                offset += 2  # tag + length
                # resultCode is first element: ENUMERATED tag 0x0A
                if data[offset] == 0x0A:
                    offset += 2  # tag + length (always 1)
                    return data[offset]
            return None
        except (IndexError, struct.error):
            return None
