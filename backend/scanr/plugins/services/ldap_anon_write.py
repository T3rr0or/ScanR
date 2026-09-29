"""Anonymous LDAP write permission.

Anonymous *read* on a directory is already reported by
``services.ldap_anon_bind``. Anonymous *write* is a different order of problem: an
unauthenticated attacker who can create objects in Active Directory can add a
computer account and use it for delegation attacks, add a DNS record to hijack a
name, or write to an object's security descriptor to escalate from nothing to
domain rights.

Read access leaks the directory. Write access is a path to owning it.

**Nothing is created by this check.** The probe sends an Add request whose
``objectClass`` is a value no schema defines. That forces the two rejections apart:

* if the bound identity has no right to create objects there, the server answers
  ``insufficientAccessRights (50)`` — the access check failed first, so the schema
  was never consulted;
* if it *does* have that right, the server proceeds to validate the entry and
  answers ``objectClassViolation (65)`` or ``namingViolation (64)`` — which is the
  server confirming permission while refusing the nonsense object.

So a 65 is proof of write access obtained without writing anything. The one case
that would create an object — an unexpected ``success`` — is reported with the
exact DN so it can be removed, but no schema accepts the class this probe sends,
so it should not occur.

Classified state-changing regardless: this sends a write operation to a production
directory, and that is not something to do outside an explicitly aggressive scan.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

LDAP_PORTS = (389, 636, 3268, 3269)
_TLS_PORTS = (636, 3269)

# LDAP result codes (RFC 4511 §4.1.9 / Appendix A).
RESULT_SUCCESS = 0
RESULT_NO_SUCH_OBJECT = 32
RESULT_INSUFFICIENT_ACCESS = 50
RESULT_OBJECT_CLASS_VIOLATION = 65
RESULT_NAMING_VIOLATION = 64
RESULT_UNWILLING_TO_PERFORM = 53
RESULT_STRONGER_AUTH_REQUIRED = 8
RESULT_CONSTRAINT_VIOLATION = 19

# Codes reached only after the access check passed — the server got as far as
# validating the entry, which means it accepted our right to create it.
WRITE_PERMITTED_CODES = frozenset({
    RESULT_OBJECT_CLASS_VIOLATION,
    RESULT_NAMING_VIOLATION,
    RESULT_CONSTRAINT_VIOLATION,
})

# A class name no schema defines, so a permitted Add still cannot succeed.
_IMPOSSIBLE_OBJECT_CLASS = "scanrNonExistentProbeClass"

_CONNECT_TIMEOUT = 8


@dataclass
class WriteProbe:
    """The outcome of one Add attempt."""

    dn: str
    result_code: int | None
    description: str = ""
    message: str = ""

    @property
    def permitted(self) -> bool:
        return self.result_code in WRITE_PERMITTED_CODES

    @property
    def created(self) -> bool:
        return self.result_code == RESULT_SUCCESS


def interpret(result_code: int | None) -> str:
    """Plain-language reading of the Add result."""
    return {
        RESULT_SUCCESS: (
            "success — the object was created, which this probe did not expect"
        ),
        RESULT_OBJECT_CLASS_VIOLATION: (
            "objectClassViolation — the server validated the entry's schema, which it "
            "only does after allowing the create"
        ),
        RESULT_NAMING_VIOLATION: (
            "namingViolation — the server evaluated the entry's naming, which it only "
            "does after allowing the create"
        ),
        RESULT_CONSTRAINT_VIOLATION: (
            "constraintViolation — the server evaluated the entry's attributes, which it "
            "only does after allowing the create"
        ),
        RESULT_INSUFFICIENT_ACCESS: (
            "insufficientAccessRights — the access check rejected the create, so writing "
            "is not permitted here"
        ),
        RESULT_NO_SUCH_OBJECT: (
            "noSuchObject — the parent container was not found, so nothing can be "
            "concluded about write permission"
        ),
        RESULT_UNWILLING_TO_PERFORM: (
            "unwillingToPerform — the server declined the operation outright"
        ),
        RESULT_STRONGER_AUTH_REQUIRED: (
            "strongerAuthRequired — the server requires a signed or TLS-protected "
            "connection for writes"
        ),
    }.get(result_code if result_code is not None else -1, f"result code {result_code}")


class LdapAnonWritePlugin(PluginBase):
    id = "services.ldap_anon_write"
    name = "Anonymous LDAP Write Access"
    description = (
        "Determine whether an anonymously-bound client may create directory "
        "objects, using an Add that no schema can accept so nothing is created"
    )
    category = PluginCategory.services
    severity = Severity.critical
    ports = list(LDAP_PORTS)

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in LDAP_PORTS or port.state != "open":
                continue
            probe = await self._probe(host.ip, port.number)
            if probe is None:
                continue
            if not (probe.permitted or probe.created):
                continue
            findings.append(self._build_finding(host.ip, port.number, probe))
        return findings

    async def _probe(self, ip: str, port: int) -> WriteProbe | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._anonymous_add, ip, port, port in _TLS_PORTS
        )

    def _anonymous_add(self, ip: str, port: int, use_tls: bool) -> WriteProbe | None:
        try:
            import ldap3
        except ImportError:
            logger.warning("ldap3 not available — skipping ldap_anon_write")
            return None

        connection = None
        try:
            server = ldap3.Server(
                ip,
                port=port,
                use_ssl=use_tls,
                get_info=ldap3.DSA,
                connect_timeout=_CONNECT_TIMEOUT,
            )
            connection = ldap3.Connection(server, authentication=ldap3.ANONYMOUS)
            if not connection.bind():
                # No anonymous bind, so there is no anonymous write to test.
                return None

            base = self._naming_context(server)
            if not base:
                return None

            dn = f"CN=scanr-write-probe-{secrets.token_hex(4)},{base}"
            connection.add(dn, object_class=_IMPOSSIBLE_OBJECT_CLASS)
            result = connection.result or {}
            code = result.get("result")
            return WriteProbe(
                dn=dn,
                result_code=code if isinstance(code, int) else None,
                description=str(result.get("description") or ""),
                message=str(result.get("message") or "")[:400],
            )
        except Exception as exc:
            logger.debug("LDAP anonymous write probe failed on %s:%d: %s", ip, port, exc)
            return None
        finally:
            if connection is not None:
                try:
                    connection.unbind()
                except Exception:
                    pass

    @staticmethod
    def _naming_context(server) -> str:
        """The directory's own base DN, read from the rootDSE."""
        info = getattr(server, "info", None)
        if info is None:
            return ""
        other = getattr(info, "other", {}) or {}
        for key in ("defaultNamingContext", "rootDomainNamingContext"):
            value = other.get(key)
            if value:
                return str(value[0] if isinstance(value, list) else value)
        contexts = getattr(info, "naming_contexts", None) or []
        for context in contexts:
            text = str(context)
            if text:
                return text
        return ""

    def _build_finding(self, ip: str, port: int, probe: WriteProbe) -> FindingData:
        reading = interpret(probe.result_code)

        if probe.created:
            return FindingData(
                plugin_id=self.id,
                severity=Severity.critical,
                title="Anonymous LDAP Write Succeeded — Object Created",
                description=(
                    f"An anonymously-bound client created an object in the directory on "
                    f"{ip}:{port}. The probe used an objectClass that no schema defines and "
                    "the server accepted it anyway, so this directory applies neither an "
                    "access check nor schema validation to unauthenticated writes.\n\n"
                    "An attacker with this access controls the directory: they can add "
                    "accounts, modify group membership, and rewrite the security "
                    "descriptors that everything else depends on.\n\n"
                    "**An object was created and must be removed manually.** Its "
                    "distinguished name is in the evidence below."
                ),
                evidence=(
                    f"Anonymous simple bind to {ip}:{port} succeeded.\n"
                    f"Add {probe.dn} with objectClass={_IMPOSSIBLE_OBJECT_CLASS}\n"
                    f"Result: {reading}\n"
                    f"Server message: {probe.message or '(none)'}\n\n"
                    f"ACTION REQUIRED: delete {probe.dn}"
                ),
                remediation=(
                    f"Delete the object named above ({probe.dn}), then disable anonymous "
                    "write access immediately.\n\n"
                    "Active Directory: anonymous operations are controlled by the 7th "
                    "character of the dSHeuristics attribute on "
                    "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,<forest "
                    "root> — it must not be 2. Review the ACL on the naming context for "
                    "grants to ANONYMOUS LOGON or Everyone.\n\n"
                    "OpenLDAP: the access rules are permitting writes to anonymous. Set "
                    "'access to * by anonymous auth' (or 'none') and grant write only to "
                    "specific authenticated identities; check for a catch-all "
                    "'by * write' rule.\n\n"
                    "Then audit the directory for objects created while this was open: "
                    "unexpected computer accounts, DNS records, and any object whose "
                    "creator is unknown. Treat the directory as potentially modified, not "
                    "merely exposed."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc4511",
                    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/anonymous-ldap-operations-active-directory-disabled",
                ],
                port_number=port,
                protocol="tcp",
            )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="Anonymous LDAP Client Is Permitted to Create Directory Objects",
            description=(
                f"The directory on {ip}:{port} accepts anonymous binds and allows an "
                "anonymously-bound client to create objects in its naming context.\n\n"
                "The server's own answer establishes this. The Add request named an "
                "objectClass that no schema defines, and the server rejected it on schema "
                "grounds rather than on access grounds — it only evaluates the schema after "
                "the access check has passed. A directory that refuses anonymous writes "
                "answers insufficientAccessRights instead, and never looks at the entry.\n\n"
                "What an attacker does with this depends on the directory, and on Active "
                "Directory it is severe. Creating a computer account provides the machine "
                "identity used in resource-based constrained delegation attacks, which lead "
                "to local administrator access on targeted hosts. Adding a record to an "
                "AD-integrated DNS zone hijacks a name — 'wpad' being the classic — and "
                "collects credentials from clients. Where write access extends to existing "
                "objects' security descriptors, it is a direct path to domain rights.\n\n"
                "This is distinct from the anonymous-read finding on the same service: read "
                "access discloses the directory, write access lets an attacker change it."
            ),
            evidence=(
                f"Anonymous simple bind to {ip}:{port} succeeded.\n"
                f"Add {probe.dn} with objectClass={_IMPOSSIBLE_OBJECT_CLASS}\n"
                f"Result: {reading}"
                + (f" ({probe.description})" if probe.description else "")
                + "\n"
                f"Server message: {probe.message or '(none)'}\n\n"
                "No object was created: the objectClass sent does not exist in any schema, "
                "so the entry could not be instantiated. The rejection reason is the "
                "evidence — a server that denied the create would have answered "
                "insufficientAccessRights (50) before reaching schema validation."
            ),
            remediation=(
                "Remove write permission from anonymous and unauthenticated principals.\n\n"
                "Active Directory: confirm anonymous operations are disabled — the 7th "
                "character of dSHeuristics on CN=Directory Service,CN=Windows NT,"
                "CN=Services,CN=Configuration,<forest root> must not be 2. Then audit the "
                "ACL on the domain naming context for entries granting Create Child, Write "
                "Property, Write DACL or Generic All to ANONYMOUS LOGON, Everyone, or "
                "Pre-Windows 2000 Compatible Access.\n\n"
                "OpenLDAP: the effective access rules allow anonymous writes. Restrict "
                "anonymous to 'auth' or 'none' and grant write only to named identities; a "
                "trailing 'by * write' is the usual cause.\n\n"
                "Separately, require LDAP signing and channel binding and prefer LDAPS, so "
                "that authenticated writes cannot be relayed either — ScanR reports those "
                "as services.ldap_signing and services.ldap_channel_binding.\n\n"
                "Finally, audit what already exists: look for computer accounts and DNS "
                "records whose creation cannot be accounted for, and reduce the "
                "ms-DS-MachineAccountQuota to 0 so machine accounts cannot be added by "
                "ordinary users either."
            ),
            references=[
                "https://datatracker.ietf.org/doc/html/rfc4511",
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/anonymous-ldap-operations-active-directory-disabled",
                "https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"ldapadd -x -H ldap://{ip}:{port} <<< $'dn: CN=probe,<base-dn>\\n"
                f"objectClass: {_IMPOSSIBLE_OBJECT_CLASS}\\n'   # 65 = write permitted, 50 = denied"
            ),
        )
