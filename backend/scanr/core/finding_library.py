"""Apply reviewed library write-ups to findings, by hand or automatically.

Applying copies the entry's description, impact, remediation, references and
CVEs into the finding. The finding's *title* is never changed: trends, triage
carry-forward and SARIF identify an issue by it. Scanner-specific text that the
library replaces is kept in the evidence, so no detail is lost.
"""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.models import Finding
from scanr.models.finding_template import FindingTemplate

_SCANNER_DETAILS = "Scanner details:"


def _list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except ValueError:
        return []
    return [str(v) for v in value] if isinstance(value, list) else []


def matches(template: FindingTemplate, plugin_id: str, title: str) -> bool:
    if plugin_id not in _list(template.plugin_ids):
        return False
    return not template.title_match or template.title_match.lower() in (title or "").lower()


def find_match(templates: list[FindingTemplate], plugin_id: str, title: str) -> FindingTemplate | None:
    """The single entry describing this finding, or None if zero or ambiguous."""
    hits = [t for t in templates if matches(t, plugin_id, title)]
    if len(hits) > 1:
        # A title-specific entry beats a catch-all for the same plugin.
        specific = [t for t in hits if t.title_match]
        hits = specific if len(specific) == 1 else []
    return hits[0] if len(hits) == 1 else None


def apply(finding: Finding, template: FindingTemplate, *, use_severity: bool = False) -> None:
    scanner_text = (finding.description or "").strip()
    if scanner_text and scanner_text != template.description.strip() and _SCANNER_DETAILS not in (finding.evidence or ""):
        finding.evidence = f"{_SCANNER_DETAILS}\n{scanner_text}" + (f"\n\n{finding.evidence}" if finding.evidence else "")
    finding.description = template.description
    finding.impact = template.impact
    finding.remediation = template.remediation or finding.remediation
    if template.references:
        merged = _list(finding.references) + [r for r in _list(template.references) if r not in _list(finding.references)]
        finding.references = json.dumps(merged)
    if template.cve_ids:
        merged = _list(finding.cve_ids) + [c for c in _list(template.cve_ids) if c not in _list(finding.cve_ids)]
        finding.cve_ids = json.dumps(merged)
    if finding.cvss_score is None and template.cvss_score is not None:
        finding.cvss_score = template.cvss_score
        finding.cvss_vector = template.cvss_vector
    if use_severity:
        finding.severity = template.severity
    finding.template_id = template.id


async def load_mappable(db: AsyncSession) -> list[FindingTemplate]:
    return list((await db.execute(
        select(FindingTemplate).where(FindingTemplate.plugin_ids.isnot(None))
    )).scalars().all())


def auto_apply(templates: list[FindingTemplate], finding: Finding) -> bool:
    template = find_match(templates, finding.plugin_id, finding.title)
    if template is None:
        return False
    apply(finding, template)
    return True


# A starter library: common internal and external findings, written for
# client reports. Seeded once into an empty library; edit freely afterwards.
STARTER: list[dict] = [
    {
        "title": "SMB signing not required",
        "severity": "medium", "cvss_score": 5.3, "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": "The host accepts SMB connections without requiring message signing. Signing proves that each SMB message comes from the authenticated party and has not been altered in transit.",
        "impact": "An attacker on the internal network can relay captured NTLM authentication to this host (NTLM relay) and act as the victim user, for example to read or change files or to execute code if the victim is an administrator. This is one of the most common paths to domain compromise in internal tests.",
        "remediation": "Require SMB signing on all servers and clients through Group Policy: \"Microsoft network server: Digitally sign communications (always)\" and \"Microsoft network client: Digitally sign communications (always)\" set to Enabled. Test legacy devices before enforcing.",
        "references": ["https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing"],
        "tags": ["internal", "active-directory"], "plugin_ids": ["services.smb_signing"],
    },
    {
        "title": "LLMNR / NBT-NS name resolution enabled",
        "severity": "medium", "cvss_score": 6.5,
        "description": "Hosts answer and send Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) queries. When DNS cannot resolve a name, Windows asks the whole local network, and any host may answer.",
        "impact": "An attacker on the same network segment can answer these broadcasts (for example with Responder), receive the victim's NTLMv2 authentication, and either crack it offline or relay it to other systems.",
        "remediation": "Disable LLMNR through Group Policy (\"Turn off multicast name resolution\" = Enabled) and disable NetBIOS over TCP/IP on all network adapters (DHCP option or adapter settings). Ensure DNS resolves all internal names.",
        "references": ["https://attack.mitre.org/techniques/T1557/001/"],
        "tags": ["internal", "active-directory"], "plugin_ids": ["services.llmnr_nbns_check"],
    },
    {
        "title": "LDAP signing and channel binding not enforced",
        "severity": "medium", "cvss_score": 5.9,
        "description": "The domain controller accepts LDAP binds that are not signed, or LDAPS binds without channel binding.",
        "impact": "Attackers who capture or coerce NTLM authentication can relay it to LDAP and modify Active Directory objects, for example to grant themselves rights, add computer accounts or configure resource-based constrained delegation, leading to privilege escalation.",
        "remediation": "Set \"Domain controller: LDAP server signing requirements\" to Require signing and \"Domain controller: LDAP server channel binding token requirements\" to Always, after auditing event 2889 for clients that would break.",
        "references": ["https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server"],
        "tags": ["internal", "active-directory"], "plugin_ids": ["services.ldap_signing"],
    },
    {
        "title": "Kerberoastable service accounts",
        "severity": "high", "cvss_score": 7.5,
        "description": "One or more user accounts have a Service Principal Name (SPN). Any authenticated domain user can request a Kerberos service ticket for these accounts, which is encrypted with a key derived from the account's password.",
        "impact": "The ticket can be cracked offline without generating failed logons. Service accounts often have weak, non-expiring passwords and high privileges, so a cracked password frequently gives access to servers or the whole domain.",
        "remediation": "Use Group Managed Service Accounts (gMSA) where possible. Otherwise set long random passwords (25+ characters), enforce AES-only Kerberos encryption for these accounts, remove unnecessary SPNs and limit their privileges.",
        "references": ["https://attack.mitre.org/techniques/T1558/003/"],
        "tags": ["internal", "active-directory"], "plugin_ids": ["services.kerberoastable"],
    },
    {
        "title": "AS-REP roastable accounts",
        "severity": "high", "cvss_score": 7.5,
        "description": "One or more accounts have Kerberos pre-authentication disabled (\"Do not require Kerberos preauthentication\").",
        "impact": "Anyone who can reach a domain controller can request authentication data for these accounts without a password and crack it offline to recover the account's password.",
        "remediation": "Enable Kerberos pre-authentication for every account unless a documented legacy system requires otherwise, and give any exception a long random password.",
        "references": ["https://attack.mitre.org/techniques/T1558/004/"],
        "tags": ["internal", "active-directory"], "plugin_ids": ["services.asreproastable"],
    },
    {
        "title": "Remote code execution in SMBv1 (MS17-010, EternalBlue)",
        "severity": "critical", "cvss_score": 8.1, "cvss_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "The host runs an SMBv1 server missing the MS17-010 security update.",
        "impact": "An unauthenticated attacker who can reach port 445 can execute code as SYSTEM. This vulnerability was used by WannaCry and NotPetya and is actively exploited.",
        "remediation": "Install the MS17-010 updates (or a later cumulative update) immediately and disable SMBv1 on all systems.",
        "references": ["https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"],
        "cve_ids": ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145"],
        "tags": ["internal", "patching"], "plugin_ids": ["services.ms17_010_check"],
    },
    {
        "title": "Anonymous FTP access",
        "severity": "medium", "cvss_score": 5.3,
        "description": "The FTP server accepts logins with the anonymous account.",
        "impact": "Anyone who can reach the server can list and download its files, and upload files if write access is allowed, which may expose sensitive data or allow the server to be used to host malicious content.",
        "remediation": "Disable anonymous FTP unless the server is intentionally public, and in that case limit it to read-only access to a dedicated directory. Prefer SFTP for authenticated transfers.",
        "tags": ["external", "internal"], "plugin_ids": ["services.ftp_anon"],
    },
    {
        "title": "Telnet service enabled",
        "severity": "medium", "cvss_score": 6.5,
        "description": "The host offers a Telnet service, which sends all data, including credentials, unencrypted.",
        "impact": "Anyone able to observe network traffic can capture usernames, passwords and session contents and take over the device.",
        "remediation": "Disable Telnet and use SSH for remote administration. If a device only supports Telnet, restrict access to a dedicated management network.",
        "tags": ["internal", "cleartext"], "plugin_ids": ["services.telnet_detect"],
    },
    {
        "title": "Default or guessable SNMP community string",
        "severity": "high", "cvss_score": 7.5,
        "description": "The device answers SNMP requests with a default or easily guessed community string such as \"public\" or \"private\".",
        "impact": "Attackers can read detailed configuration, interfaces, routing tables, running processes and sometimes credentials. With a write community they can change the device configuration.",
        "remediation": "Change community strings to long random values, restrict SNMP to management hosts with ACLs, and migrate to SNMPv3 with authentication and encryption.",
        "tags": ["internal", "network"], "plugin_ids": ["services.snmp_community"],
    },
    {
        "title": "Redis accessible without authentication",
        "severity": "high", "cvss_score": 8.8,
        "description": "The Redis server accepts commands from any client without a password.",
        "impact": "Attackers can read and modify all cached data, and Redis features such as CONFIG SET and MODULE LOAD are commonly abused to write files or execute code on the server.",
        "remediation": "Bind Redis to localhost or a private interface, require authentication (requirepass or ACL users), rename or disable dangerous commands, and restrict access with a firewall.",
        "tags": ["internal", "database"], "plugin_ids": ["services.redis_unauth"],
    },
    {
        "title": "Outdated TLS protocol versions supported",
        "severity": "medium", "cvss_score": 5.9,
        "description": "The service accepts SSL 3.0, TLS 1.0 or TLS 1.1. These versions are deprecated (RFC 8996) and rely on weak cryptographic constructions.",
        "impact": "Connections that negotiate these versions are exposed to known downgrade and decryption attacks, and the configuration fails PCI DSS and most compliance baselines.",
        "remediation": "Disable SSL 3.0, TLS 1.0 and TLS 1.1. Support TLS 1.2 with AEAD cipher suites and TLS 1.3.",
        "references": ["https://datatracker.ietf.org/doc/html/rfc8996"],
        "tags": ["external", "tls"], "plugin_ids": ["ssl_tls.protocol_check"],
    },
    {
        "title": "Missing Content-Security-Policy header",
        "severity": "low", "cvss_score": 3.1,
        "description": "The web application does not send a Content-Security-Policy (CSP) header. CSP tells the browser which sources of scripts, styles and other content the page may load.",
        "impact": "Without a CSP, any cross-site scripting flaw in the application is fully exploitable, because injected scripts run without restriction.",
        "remediation": "Define a restrictive Content-Security-Policy, starting with default-src 'self' and explicit allowances, and avoid 'unsafe-inline'. Deploy in report-only mode first to find violations.",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
        "tags": ["web", "headers"], "plugin_ids": ["web.http_headers"], "title_match": "Content Security Policy Not Set",
    },
    {
        "title": "Clickjacking protection missing",
        "severity": "low", "cvss_score": 4.3,
        "description": "The application can be embedded in a frame on another site because it sets neither X-Frame-Options nor a CSP frame-ancestors directive.",
        "impact": "An attacker can overlay the application in an invisible frame on a malicious page and trick users into clicking buttons, for example to change settings or approve actions.",
        "remediation": "Send Content-Security-Policy: frame-ancestors 'none' (or 'self' if framing is needed) and X-Frame-Options: DENY for older browsers.",
        "references": ["https://owasp.org/www-community/attacks/Clickjacking"],
        "tags": ["web", "headers"], "plugin_ids": ["web.clickjacking"],
    },
    {
        "title": "Session cookies without secure attributes",
        "severity": "low", "cvss_score": 4.3,
        "description": "One or more cookies are set without the Secure, HttpOnly or SameSite attribute.",
        "impact": "Cookies without Secure can be sent over unencrypted connections, without HttpOnly they can be read by injected scripts, and without SameSite they are sent with cross-site requests, which helps session hijacking and CSRF.",
        "remediation": "Set Secure and HttpOnly on all session cookies, and SameSite=Lax or Strict unless cross-site use is required.",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"],
        "tags": ["web"], "plugin_ids": ["web.cookie_security"],
    },
    {
        "title": "Directory listing enabled",
        "severity": "low", "cvss_score": 5.3,
        "description": "The web server returns a list of files when a directory without an index page is requested.",
        "impact": "Visitors can browse files that were never meant to be linked, such as backups, configuration files or internal documents.",
        "remediation": "Disable automatic directory indexes (for example Options -Indexes in Apache, autoindex off in nginx) and remove files that should not be public.",
        "tags": ["web"], "plugin_ids": ["web.dir_listing"],
    },
    {
        "title": "SQL injection",
        "severity": "critical", "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "User input is included in a database query without proper parameterisation, so input can change the structure of the query.",
        "impact": "An attacker can read or modify data in the database, bypass authentication, and depending on the database configuration execute commands on the server.",
        "remediation": "Use parameterised queries or prepared statements for all database access, never build SQL with string concatenation, apply least-privilege database accounts, and validate input against expected formats.",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
        "tags": ["web", "injection"], "plugin_ids": ["web.sqli_detect", "web.sqli_blind"],
    },
    {
        "title": "Cross-site scripting (XSS)",
        "severity": "high", "cvss_score": 6.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "description": "The application includes user-controlled input in its pages without encoding it for the context in which it appears, so the input can contain script that runs in the victim's browser.",
        "impact": "An attacker can run JavaScript in a victim's session to steal session data, perform actions as the user, or show fake login forms.",
        "remediation": "Encode all output for its context (HTML, attribute, JavaScript, URL), use a templating framework that escapes by default, and add a restrictive Content-Security-Policy as defence in depth.",
        "references": ["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
        "tags": ["web", "injection"], "plugin_ids": ["web.xss_detect"],
    },
]


async def seed(db: AsyncSession) -> int:
    """Add the starter library once, into an empty library only."""
    if (await db.execute(select(FindingTemplate.id).limit(1))).first():
        return 0
    for entry in STARTER:
        db.add(FindingTemplate(
            title=entry["title"], severity=entry["severity"],
            cvss_score=entry.get("cvss_score"), cvss_vector=entry.get("cvss_vector"),
            description=entry["description"], impact=entry.get("impact"), remediation=entry.get("remediation"),
            references=json.dumps(entry["references"]) if entry.get("references") else None,
            cve_ids=json.dumps(entry["cve_ids"]) if entry.get("cve_ids") else None,
            tags=json.dumps(entry["tags"]) if entry.get("tags") else None,
            plugin_ids=json.dumps(entry["plugin_ids"]) if entry.get("plugin_ids") else None,
            title_match=entry.get("title_match"), created_by="ScanR starter library",
        ))
    await db.commit()
    return len(STARTER)
