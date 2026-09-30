"""Active Directory domain/forest trust enumeration over secure LDAP."""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.services._ldap_secure import LdapTlsError, warn_ldap_tls

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)
TRUST_PORTS = [389, 636, 3268, 3269]


class TrustEnumPlugin(PluginBase):
    id = "services.trust_enum"
    name = "AD Domain / Forest Trust Enumeration"
    description = "Enumerate Active Directory trusts using authenticated LDAP"
    category = PluginCategory.services
    severity = Severity.medium
    ports = TRUST_PORTS
    requires_auth = True

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        cred = context.credential("windows") or context.credential("generic")
        if not cred or not cred.get("username") or not cred.get("domain"):
            return []
        # LDAP simple binds are only allowed over the encrypted standard ports.
        tls_error: LdapTlsError | None = None
        tls_ok = False  # some port got past TLS, so the certificate is not the problem
        for port in host.ports:
            if port.number not in (389, 636, 3268, 3269) or port.state != "open":
                continue
            try:
                trusts = await self._enumerate_trusts(host.ip, port.number, cred, host.hostname)
            except LdapTlsError as exc:
                tls_error = exc  # another port may still validate
                continue
            tls_ok = True
            if trusts:
                return [self._build_finding(host.ip, port.number, trusts)]
        if tls_error is not None and not tls_ok:
            await warn_ldap_tls(context, self.id, host.ip, tls_error)
        return []

    async def _enumerate_trusts(self, ip: str, port: int, cred: dict,
                                hostname: str | None = None) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._ldap_trusts, ip, port, cred, hostname)

    def _ldap_trusts(self, ip: str, port: int, cred: dict,
                     hostname: str | None = None) -> list[dict]:
        try:
            import ldap3
            from scanr.plugins.services._ldap_secure import secure_ldap_connection

            domain = cred["domain"]
            bind_user = cred["username"]
            if "\\" not in bind_user and "@" not in bind_user:
                bind_user = f"{domain}\\{bind_user}"
            conn = secure_ldap_connection(
                ldap3, ip, port, bind_user, cred.get("password", ""),
                hostnames=(hostname,),
            )
            try:
                base_dn = "CN=System," + ",".join(
                    f"DC={part}" for part in domain.split(".") if part
                )
                conn.search(
                    base_dn,
                    "(objectClass=trustedDomain)",
                    attributes=[
                        "trustPartner", "trustDirection", "trustType", "trustAttributes"
                    ],
                )
                return parse_trust_entries(conn.entries)
            finally:
                conn.unbind()
        except LdapTlsError:
            raise
        except Exception as exc:
            logger.debug("LDAP trust enumeration failed for %s:%s: %s", ip, port, exc)
            return []

    def _build_finding(self, ip: str, port: int, trusts: list[dict]) -> FindingData:
        # Discovery is useful inventory, but trust metadata alone does not prove
        # an exploitable path or disabled SID filtering.
        evidence = "\n".join(
            f"{t['target']} — type={t['type']}, direction={t['direction']}, "
            f"transitive={t['transitive']}"
            for t in trusts[:100]
        )
        return FindingData(
            plugin_id=self.id,
            severity=Severity.info,
            title=f"AD Trust Enumeration — {len(trusts)} trust(s) discovered",
            description=(
                f"Authenticated LDAP found {len(trusts)} trust relationship(s). "
                "Review each relationship and its SID filtering and selective "
                "authentication settings in the domain configuration."
            ),
            evidence=f"Domain controller: {ip}:{port}\n{evidence}",
            remediation=(
                "Review whether each trust is still required. Verify SID filtering, "
                "selective authentication, and permitted cross-domain access using "
                "the domain's administrative tooling."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1482/",
                "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/understanding-trusts",
            ],
            port_number=port,
            protocol="tcp",
        )


def _as_int(entry, attr: str) -> int | None:
    try:
        value = getattr(entry, attr)
        return int(str(value))
    except (AttributeError, TypeError, ValueError):
        return None


def parse_trust_entries(entries) -> list[dict]:
    """Map ldap3 trustedDomain entries to stable, non-speculative metadata."""
    directions = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
    types = {1: "downlevel", 2: "up-level", 3: "mit", 4: "dce"}
    trusts = []
    for entry in entries:
        target = str(entry.trustPartner) if hasattr(entry, "trustPartner") else entry.entry_dn
        direction = _as_int(entry, "trustDirection")
        trust_type = _as_int(entry, "trustType")
        attrs = _as_int(entry, "trustAttributes") or 0
        trusts.append({
            "target": target,
            "type": "forest" if attrs & 0x8 else types.get(trust_type or -1, "unknown"),
            "direction": directions.get(direction if direction is not None else -1, "unknown"),
            "transitive": not bool(attrs & 0x1),
        })
    return trusts
