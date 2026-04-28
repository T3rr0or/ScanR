"""DCSync privilege check.

Detects non-Domain Controller accounts that hold both DS-Replication-Get-Changes
and DS-Replication-Get-Changes-All extended rights on the domain root object,
enabling them to replicate all domain credentials via DCSync.
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


class DcSyncCheckPlugin(PluginBase):
    id = "services.dcsync_check"
    name = "DCSync Privilege Check"
    description = "Check if non-DC accounts have DCSync privileges (DS-Replication-Get-Changes-All)"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [389]
    requires_auth = True

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        open_ports = {p.number for p in host.ports if p.state == "open"}
        if 389 not in open_ports:
            return []

        creds = context.credential_data or {}
        username = creds.get("username", "")
        password = creds.get("password", "")
        domain = creds.get("domain", "")
        if not username or not domain:
            return []

        return await asyncio.get_event_loop().run_in_executor(
            None, self._check_dcsync, host.ip, username, password, domain
        )

    def _check_dcsync(self, ip: str, username: str, password: str, domain: str) -> list[FindingData]:
        try:
            import ldap3
            from ldap3.protocol.microsoft import security_descriptor_control
        except ImportError:
            logger.debug("ldap3 not available")
            return []

        base_dn = ",".join(f"DC={part}" for part in domain.split(".") if part)
        bind_user = f"{domain}\\{username}" if "\\" not in username else username

        try:
            server = ldap3.Server(ip, port=389, get_info=ldap3.ALL, connect_timeout=10)
            conn = ldap3.Connection(server, user=bind_user, password=password, auto_bind=True, receive_timeout=15)

            # Request nTSecurityDescriptor with DACL
            # Use SD_FLAGS control to get DACL only (flag 0x04)
            controls = security_descriptor_control(sdflags=0x04)

            conn.search(
                base_dn,
                "(objectClass=domain)",
                attributes=["nTSecurityDescriptor", "distinguishedName"],
                controls=controls,
            )

            if not conn.entries:
                conn.unbind()
                return []

            entry = conn.entries[0]
            sd = entry["nTSecurityDescriptor"].raw_values[0] if entry["nTSecurityDescriptor"].raw_values else None

            if not sd:
                conn.unbind()
                return []

            # Parse security descriptor and check for DCSync rights
            vulnerable_accounts = self._parse_dcsync_dacl(conn, sd, base_dn, ip)
            conn.unbind()

            if not vulnerable_accounts:
                return []

            return [FindingData(
                plugin_id=self.id,
                severity=Severity.critical,
                title=f"DCSync Privilege Detected — {len(vulnerable_accounts)} Account(s)",
                description=(
                    "One or more non-Domain Controller accounts have DCSync privileges "
                    "(DS-Replication-Get-Changes-All). These accounts can replicate all domain "
                    "credentials including KRBTGT hash, enabling Golden Ticket attacks and "
                    "full domain compromise via secretsdump."
                ),
                evidence="Accounts with DCSync rights:\n" + "\n".join(f"  {a}" for a in vulnerable_accounts[:20]),
                remediation=(
                    "Remove DS-Replication-Get-Changes-All from non-DC accounts via ADSI Edit. "
                    "Audit all accounts with replication rights quarterly. "
                    "Enable and monitor 'Directory Service Replication' audit events (Event ID 4662)."
                ),
                references=[
                    "https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync",
                    "https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all",
                ],
                port_number=389,
                protocol="tcp",
            )]
        except Exception as exc:
            logger.debug("DCSync check failed on %s: %s", ip, exc)
            return []

    def _parse_dcsync_dacl(self, conn, sd_bytes: bytes, base_dn: str, ip: str) -> list[str]:
        """Parse DACL for DCSync rights. Returns list of account names with both replication rights."""
        try:
            import ldap3
            from ldap3.protocol.formatters.formatters import format_sid
            import struct

            REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
            REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

            # Parse security descriptor
            # SD header: revision(1) + sbz1(1) + control(2) + offsetOwner(4) + offsetGroup(4) + offsetSacl(4) + offsetDacl(4)
            if len(sd_bytes) < 20:
                return []

            offset_dacl = struct.unpack_from("<I", sd_bytes, 16)[0]
            if offset_dacl == 0 or offset_dacl >= len(sd_bytes):
                return []

            dacl = sd_bytes[offset_dacl:]
            if len(dacl) < 8:
                return []

            # DACL header: revision(1) + sbz1(1) + size(2) + ace_count(2) + sbz2(2)
            ace_count = struct.unpack_from("<H", dacl, 4)[0]

            # Track which accounts have which rights
            repl_accounts: dict[str, set] = {}

            offset = 8
            for _ in range(min(ace_count, 500)):
                if offset >= len(dacl):
                    break
                # ACE header: type(1) + flags(1) + size(2)
                if len(dacl) < offset + 4:
                    break
                ace_type = dacl[offset]
                ace_size = struct.unpack_from("<H", dacl, offset + 2)[0]
                if ace_size < 4 or offset + ace_size > len(dacl):
                    break

                ace_data = dacl[offset:offset + ace_size]

                # Type 0x05 = ACCESS_ALLOWED_OBJECT_ACE (extended rights)
                if ace_type == 0x05 and len(ace_data) >= 40:
                    flags = struct.unpack_from("<I", ace_data, 4)[0]
                    object_type_offset = 12  # after header(4) + mask(4) + flags(4)

                    if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                        # Object type GUID (16 bytes)
                        guid_bytes = ace_data[object_type_offset:object_type_offset + 16]
                        if len(guid_bytes) == 16:
                            # Convert to string GUID
                            d1 = struct.unpack_from("<I", guid_bytes, 0)[0]
                            d2 = struct.unpack_from("<H", guid_bytes, 4)[0]
                            d3 = struct.unpack_from("<H", guid_bytes, 6)[0]
                            d4 = guid_bytes[8:16].hex()
                            guid_str = f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[:4]}-{d4[4:]}"

                            sid_offset = object_type_offset + 16
                            if flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                                sid_offset += 16

                            if guid_str in (REPL_GET_CHANGES, REPL_GET_CHANGES_ALL):
                                # Get SID
                                sid_bytes = ace_data[sid_offset:]
                                try:
                                    sid = format_sid(sid_bytes)
                                    if sid and not self._is_dc_sid(sid):
                                        if sid not in repl_accounts:
                                            repl_accounts[sid] = set()
                                        repl_accounts[sid].add(guid_str)
                                except Exception:
                                    pass

                offset += ace_size

            # Accounts with BOTH rights
            vulnerable_sids = [
                sid for sid, rights in repl_accounts.items()
                if REPL_GET_CHANGES in rights and REPL_GET_CHANGES_ALL in rights
            ]

            # Try to resolve SIDs to names
            names = []
            for sid in vulnerable_sids[:10]:
                try:
                    conn.search(
                        base_dn,
                        f"(objectSid={sid})",
                        attributes=["sAMAccountName", "distinguishedName"],
                        search_scope=ldap3.SUBTREE,
                    )
                    if conn.entries:
                        name = str(conn.entries[0].sAMAccountName) if conn.entries[0].sAMAccountName else sid
                        names.append(name)
                    else:
                        names.append(sid)
                except Exception:
                    names.append(sid)

            return names
        except Exception as exc:
            logger.debug("DACL parse error: %s", exc)
            return []

    def _is_dc_sid(self, sid: str) -> bool:
        """Domain Controllers: S-1-5-9 (Enterprise DCs), RID 516 (Domain Controllers group), RID 521 (Read-Only DCs)."""
        if sid == "S-1-5-9":
            return True
        parts = sid.split("-")
        return len(parts) > 1 and parts[-1] in ("516", "521")
