"""LDAP user and group enumeration via authenticated bind.

Requires primary_domain credentials. Enumerates domain users, groups,
and computers. Flags privileged group membership and stale accounts.
"""
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
from scanr.plugins.services._ldap_secure import LdapTlsError, run_ldap_check
from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

class LdapUserEnumPlugin(PluginBase):
    id = "services.ldap_user_enum"
    name = "LDAP User Enumeration"
    description = "Enumerate AD users, groups, and computers via authenticated LDAP"
    category = PluginCategory.services
    severity = Severity.info
    requires_auth = True
    ports = [389, 636]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        has_ldap = any(p.number in (389, 636) and p.state == "open" for p in host.ports)
        if not has_ldap:
            return []
        creds = context.credential("primary_domain") or context.credential_data
        if not creds or not creds.get("username"):
            return []

        username = creds["username"]
        password = creds.get("password", "")
        domain = creds.get("domain", "")

        open_ports = [p.number for p in host.ports if p.number in (389, 636) and p.state == "open"]
        results = await run_ldap_check(
            context, self.id, host.ip, self._enumerate_ldap,
            host.ip, username, password, domain, open_ports, host.hostname,
        )
        return results

    def _enumerate_ldap(self, ip: str, username: str, password: str, domain: str,
                        open_ports: list[int] | None = None,
                        hostname: str | None = None) -> list[FindingData]:
        try:
            import ldap3
        except ImportError:
            logger.warning("ldap3 not installed — skipping ldap_user_enum")
            return []

        findings = []
        tls_error: LdapTlsError | None = None
        tls_ok = False  # some port got past TLS, so the certificate is not the problem
        # Build base DN from domain
        if domain:
            base_dn = ",".join(f"DC={part}" for part in domain.replace("\\", "").split(".") if part)
        else:
            base_dn = ""

        from scanr.plugins.services._ldap_secure import secure_ldap_connection
        # Prefer LDAPS, then use LDAP only after StartTLS succeeds. Never bind
        # with a password on an unencrypted LDAP connection.
        for port in (p for p in (636, 389) if open_ports is None or p in open_ports):
            try:
                # Build UPN or domain\user bind
                bind_user = f"{domain}\\{username}" if domain and "\\" not in username else username
                conn = secure_ldap_connection(
                    ldap3, ip, port, bind_user, password, hostnames=(hostname,)
                )

                if not base_dn:
                    # Try to get base DN from rootDSE
                    base_dn = conn.server.info.other.get("defaultNamingContext", [""])[0] if conn.server.info else ""

                if not base_dn:
                    conn.unbind()
                    continue

                # Enumerate users
                conn.search(base_dn, "(objectClass=user)", attributes=["sAMAccountName", "memberOf", "userAccountControl", "lastLogon", "pwdLastSet"])
                users = list(conn.entries)

                # Enumerate Domain Admins group
                conn.search(base_dn, "(&(objectClass=group)(sAMAccountName=Domain Admins))", attributes=["member"])
                da_members = set()
                if conn.entries:
                    members = conn.entries[0].member.values if hasattr(conn.entries[0], "member") else []
                    da_members = {str(m) for m in members}

                # Enumerate computers
                conn.search(base_dn, "(objectClass=computer)", attributes=["sAMAccountName", "operatingSystem", "lastLogon"])
                computers = list(conn.entries)

                conn.unbind()

                # Build summary finding
                user_count = len(users)
                computer_count = len(computers)
                da_count = len(da_members)

                # Find privileged accounts
                privileged_names = []
                for entry in users:
                    try:
                        sam = str(entry.sAMAccountName)
                        dn = entry.entry_dn
                        if dn in da_members:
                            privileged_names.append(f"{sam} (Domain Admin)")
                    except Exception:
                        pass

                evidence_lines = [
                    f"Domain: {domain or 'unknown'}",
                    f"Total users: {user_count}",
                    f"Total computers: {computer_count}",
                    f"Domain Admins: {da_count}",
                ]
                if privileged_names:
                    evidence_lines.append("Privileged accounts found:")
                    evidence_lines.extend(f"  {n}" for n in privileged_names[:20])

                sev = Severity.medium if da_count > 3 else Severity.info

                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=sev,
                    title=f"Active Directory Enumeration — {user_count} users, {da_count} Domain Admins",
                    description=(
                        f"Authenticated LDAP enumeration revealed {user_count} user accounts and "
                        f"{computer_count} computer accounts. {da_count} Domain Admin account(s) identified. "
                        "This information can be used by attackers to plan targeted attacks."
                    ),
                    evidence="\n".join(evidence_lines),
                    port_number=port,
                    protocol="tcp",
                    remediation="Restrict LDAP access to authorised management workstations. "
                                "Review Domain Admin membership and apply least-privilege.",
                ))
                return findings  # success on first working port

            except LdapTlsError as exc:
                tls_error = exc  # try the next port before reporting
            except Exception as exc:
                tls_ok = True
                logger.debug("LDAP enum failed on %s:%s — %s", ip, port, exc)

        if not findings and tls_error is not None and not tls_ok:
            raise tls_error
        return findings
