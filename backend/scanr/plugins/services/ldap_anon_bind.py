"""LDAP anonymous bind check.

An anonymous LDAP bind allows unauthenticated clients to query directory
information — user accounts, groups, domain structure — without credentials.
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

_LDAP_PORTS = (389, 636, 3268, 3269)


class LdapAnonBindPlugin(PluginBase):
    id = "services.ldap_anon_bind"
    name = "LDAP Anonymous Bind"
    description = "Check if LDAP server accepts unauthenticated (anonymous) bind requests"
    category = PluginCategory.services
    severity = Severity.medium
    ports = list(_LDAP_PORTS)

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in _LDAP_PORTS or port.state != "open":
                continue
            use_tls = port.number in (636, 3269)
            info = await asyncio.get_running_loop().run_in_executor(
                None, self._try_anon_bind, host.ip, port.number, use_tls
            )
            if info is not None:
                evidence_lines = [f"Anonymous LDAP bind succeeded on {host.ip}:{port.number}"]
                if info.get("naming_context"):
                    evidence_lines.append(f"rootDomainNamingContext: {info['naming_context']}")
                if info.get("domain"):
                    evidence_lines.append(f"Domain: {info['domain']}")
                if info.get("dc_functional"):
                    evidence_lines.append(f"domainControllerFunctionality: {info['dc_functional']}")

                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="LDAP Anonymous Bind Accepted",
                    description=(
                        "The LDAP server accepts anonymous (unauthenticated) bind requests. "
                        "This allows attackers to query directory objects including user accounts, "
                        "groups, computers, and domain configuration without any credentials."
                    ),
                    evidence="\n".join(evidence_lines),
                    remediation=(
                        "Disable anonymous LDAP access. On Active Directory, ensure "
                        "'DS-Heuristics' attribute has the 2nd character set to 0 (default). "
                        "For other LDAP servers, set 'allow_anon_bind = no' in the server config."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/anonymous-ldap-operations-active-directory-disabled",
                    ],
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    def _try_anon_bind(self, ip: str, port: int, use_tls: bool) -> dict | None:
        try:
            import ldap3
        except ImportError:
            return self._try_anon_bind_socket(ip, port)

        try:
            server = ldap3.Server(
                ip,
                port=port,
                use_ssl=use_tls,
                get_info=ldap3.ALL,
                connect_timeout=8,
            )
            conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS)
            if not conn.bind():
                return None
            info: dict = {}
            if server.info:
                nc = server.info.other.get("rootDomainNamingContext")
                if nc:
                    info["naming_context"] = nc[0] if isinstance(nc, list) else nc
                    # Extract domain from DC= components
                    parts = [p.split("=", 1)[1] for p in str(info["naming_context"]).split(",") if p.upper().startswith("DC=") and len(p.split("=", 1)) > 1]
                    if parts:
                        info["domain"] = ".".join(parts)
                dcf = server.info.other.get("domainControllerFunctionality")
                if dcf:
                    info["dc_functional"] = dcf[0] if isinstance(dcf, list) else dcf
            conn.unbind()
            return info
        except Exception as exc:
            logger.debug("LDAP anon bind failed on %s:%d: %s", ip, port, exc)
            return None

    def _try_anon_bind_socket(self, ip: str, port: int) -> dict | None:
        """Fallback when ldap3 is unavailable — raw LDAP bind request."""
        import socket
        # BER-encoded LDAP BindRequest: version=3, name="", simple auth=""
        bind_req = bytes.fromhex(
            "300c"      # SEQUENCE, length 12
            "0201 01"   # messageID = 1
            "6007"      # BindRequest (app 0), length 7
            "0201 03"   # version = 3
            "0400"      # name = "" (empty DN)
            "8000"      # simple auth = "" (empty password)
        ).replace(b" ", b"")
        try:
            sock = socket.create_connection((ip, port), timeout=8)
            sock.sendall(bind_req)
            resp = sock.recv(256)
            sock.close()
            # BindResponse resultCode is at fixed offset; 0x00 = success
            if len(resp) > 7 and resp[7] == 0x00:
                return {}
        except Exception:
            pass
        return None
