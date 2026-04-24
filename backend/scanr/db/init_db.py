from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.auth.password import hash_password
from scanr.config import get_settings
from scanr.models import Plugin, User, UserRole
from scanr.models.base import new_uuid
from scanr.models.scan_template import ScanTemplate

logger = logging.getLogger(__name__)
settings = get_settings()

_ALEMBIC_INI = Path(__file__).parent.parent.parent / "alembic.ini"


def _sync_upgrade() -> None:
    from alembic.config import Config
    from alembic import command

    cfg = Config(str(_ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(cfg, "head")


async def run_migrations() -> None:
    """Apply all pending Alembic migrations. Safe to call on every startup."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _sync_upgrade)
    logger.info("Database migrations applied")


async def seed_admin(session: AsyncSession) -> None:
    from sqlalchemy import select

    result = await session.execute(select(User).where(User.email == settings.admin_email))
    if result.scalar_one_or_none():
        return

    admin = User(
        id=new_uuid(),
        email=settings.admin_email,
        hashed_password=hash_password(settings.admin_password),
        full_name="Administrator",
        role=UserRole.admin,
        is_active=True,
    )
    session.add(admin)
    await session.commit()
    logger.info("Admin user seeded: %s", settings.admin_email)


async def seed_plugins(session: AsyncSession) -> None:
    """Insert plugin metadata rows if not present."""
    from sqlalchemy import select

    BUILTIN_PLUGINS = [
        # SSL/TLS
        dict(id="ssl_tls.cert_inspector", name="SSL Certificate Inspector", category="ssl_tls", default_severity="medium", description="Check certificate expiry, weak signature, and CN mismatch"),
        dict(id="ssl_tls.cipher_audit", name="Weak Cipher Suite Detection", category="ssl_tls", default_severity="high", description="Detect RC4, DES, NULL, and export cipher suites"),
        dict(id="ssl_tls.protocol_check", name="Deprecated TLS/SSL Protocol", category="ssl_tls", default_severity="high", description="Detect SSLv2, SSLv3, TLS 1.0, TLS 1.1 support"),
        dict(id="ssl_tls.heartbleed", name="Heartbleed (CVE-2014-0160)", category="ssl_tls", default_severity="critical", cve_ids='["CVE-2014-0160"]', description="Test for OpenSSL Heartbleed vulnerability"),
        dict(id="ssl_tls.poodle_beast", name="POODLE/BEAST (CVE-2014-3566)", category="ssl_tls", default_severity="high", cve_ids='["CVE-2014-3566","CVE-2011-3389"]', description="Test for POODLE and BEAST vulnerabilities"),
        # Web
        dict(id="web.http_headers", name="Missing Security Headers", category="web", default_severity="medium", description="Check for missing X-Content-Type-Options, HSTS, CSP, etc."),
        dict(id="web.http_methods", name="Dangerous HTTP Methods", category="web", default_severity="medium", description="Detect enabled TRACE, PUT, DELETE methods"),
        dict(id="web.dir_listing", name="Directory Listing Enabled", category="web", default_severity="medium", description="Detect web server directory listing"),
        dict(id="web.default_creds_web", name="Default Web Credentials", category="web", default_severity="critical", description="Test for default admin credentials on web interfaces"),
        dict(id="web.cors_misconfig", name="CORS Misconfiguration", category="web", default_severity="high", description="Detect wildcard CORS or credentials with wildcard origin"),
        dict(id="web.clickjacking", name="Clickjacking (X-Frame-Options)", category="web", default_severity="medium", description="Detect missing X-Frame-Options or CSP frame-ancestors"),
        # Services
        dict(id="services.ftp_anon", name="FTP Anonymous Access", category="services", default_severity="high", description="Test FTP server for anonymous login"),
        dict(id="services.smtp_open_relay", name="SMTP Open Relay", category="services", default_severity="high", description="Test SMTP server for open relay"),
        dict(id="services.snmp_community", name="SNMP Default Community Strings", category="services", default_severity="high", description="Brute-force common SNMP community strings"),
        dict(id="services.rdp_check", name="RDP Security Check", category="services", default_severity="high", cve_ids='["CVE-2019-0708"]', description="Check for BlueKeep and NLA enforcement"),
        dict(id="services.smb_signing", name="SMB Signing Disabled", category="services", default_severity="medium", description="Check if SMB signing is required"),
        dict(id="services.smb_vulns", name="EternalBlue (MS17-010)", category="services", default_severity="critical", cve_ids='["CVE-2017-0144"]', description="Check for MS17-010 EternalBlue vulnerability"),
        dict(id="services.telnet_detect", name="Telnet Service Detected", category="services", default_severity="high", description="Flag plaintext Telnet service"),
        dict(id="services.vnc_auth", name="VNC Authentication Check", category="services", default_severity="high", description="Check for VNC no-auth or weak authentication"),
        dict(id="services.dns_zone_transfer", name="DNS Zone Transfer (AXFR)", category="services", default_severity="high", description="Attempt DNS zone transfer"),
        dict(id="services.ntp_monlist", name="NTP Monlist Amplification", category="services", default_severity="medium", cve_ids='["CVE-2013-5211"]', description="Check for NTP monlist amplification"),
        dict(id="services.netbios_info", name="NetBIOS Information", category="network", default_severity="info", description="Enumerate NetBIOS names and workgroup"),
        # SSH
        dict(id="ssh.ssh_algos", name="Weak SSH Algorithms", category="ssh", default_severity="medium", description="Detect weak KEX, cipher, and MAC algorithms"),
        dict(id="ssh.ssh_version", name="Vulnerable SSH Version", category="ssh", default_severity="high", description="Flag known-vulnerable OpenSSH/Dropbear versions"),
        dict(id="ssh.ssh_default_creds", name="SSH Default Credentials", category="ssh", default_severity="critical", description="Test common default SSH username/password pairs"),
        # Network
        dict(id="network.open_ports_info", name="Open Ports Inventory", category="network", default_severity="info", description="Document all open ports"),
        dict(id="network.icmp_info", name="ICMP Information", category="network", default_severity="info", description="Document ICMP response types"),
        # CVE
        dict(id="cve.cve_matcher", name="CVE Version Matcher", category="cve", default_severity="info", description="Match detected service versions against NVD CVE database"),
        # Web — screenshots
        dict(id="web.screenshot", name="Web Screenshot", category="web", default_severity="info", description="Capture Aquatone-style screenshots of all HTTP/HTTPS services"),
        # New web plugins
        dict(id="web.open_redirect", name="Open Redirect", category="web", default_severity="medium", description="Test for open redirect vulnerabilities via common redirect parameters"),
        dict(id="web.path_traversal", name="Path Traversal / LFI", category="web", default_severity="high", description="Test for path traversal and local file inclusion vulnerabilities"),
        dict(id="web.jwt_misconfig", name="JWT Misconfiguration", category="web", default_severity="high", description="Detect JWT alg:none attack and weak HMAC signing secrets"),
        dict(id="web.graphql_introspection", name="GraphQL Introspection Enabled", category="web", default_severity="info", description="Detect exposed GraphQL endpoints with introspection enabled"),
        dict(id="web.sensitive_files", name="Sensitive File Exposure", category="web", default_severity="critical", description="Check for exposed sensitive files: .git, .env, backups, phpinfo"),
        dict(id="web.dir_bruteforce", name="Directory Bruteforce", category="web", default_severity="info", description="Enumerate common HTTP paths to discover hidden endpoints and admin panels"),
        # Unauthenticated service plugins
        dict(id="services.redis_unauth", name="Redis Unauthenticated Access", category="services", default_severity="critical", description="Detect Redis instances with no authentication required"),
        dict(id="services.elasticsearch_unauth", name="Elasticsearch Unauthenticated Access", category="services", default_severity="critical", description="Detect Elasticsearch instances accessible without authentication"),
        dict(id="services.mongodb_unauth", name="MongoDB Unauthenticated Access", category="services", default_severity="critical", description="Detect MongoDB instances accessible without authentication"),
        dict(id="services.docker_daemon_unauth", name="Docker Daemon Exposed", category="services", default_severity="critical", description="Detect Docker daemon TCP socket exposed without authentication"),
        dict(id="services.kubernetes_api_unauth", name="Kubernetes API Unauthenticated Access", category="services", default_severity="critical", description="Detect exposed Kubernetes API server with anonymous access"),
        dict(id="services.jupyter_unauth", name="Jupyter Notebook Unauthenticated Access", category="services", default_severity="critical", description="Detect Jupyter Notebook instances accessible without token or password"),
        dict(id="services.ipmi_cipher_zero", name="IPMI Cipher Suite 0 Auth Bypass", category="services", default_severity="critical", cve_ids='["CVE-2013-4786"]', description="Detect IPMI 2.0 BMCs vulnerable to Cipher 0 auth bypass"),
        # Nuclei
        dict(id="nuclei.runner", name="Nuclei Template Scanner", category="web", default_severity="info", description="Run Nuclei vulnerability scanner templates against HTTP/HTTPS services"),
        # New service plugins
        dict(id="services.smb_null_session", name="SMB NULL Session", category="services", default_severity="medium", description="Test SMB for unauthenticated NULL session access and share enumeration"),
        dict(id="services.smb_share_enum", name="SMB Share Enumeration", category="services", default_severity="medium", description="Enumerate SMB shares and test for writable access", requires_auth=True),
        dict(id="services.ldap_anon_bind", name="LDAP Anonymous Bind", category="services", default_severity="medium", description="Test LDAP server for anonymous bind access and naming context exposure"),
        dict(id="services.ad_password_policy", name="AD Password Policy", category="services", default_severity="medium", description="Retrieve Active Directory domain password policy via SAMR and flag weak settings", requires_auth=True),
        dict(id="services.rdp_info", name="RDP Certificate Info", category="services", default_severity="info", description="Read RDP TLS certificate to extract hostname, domain, and FQDN"),
        dict(id="services.ike_aggressive_mode", name="IKEv1 Aggressive Mode", category="services", default_severity="high", description="Detect IKEv1 Aggressive Mode which exposes the PSK hash to offline cracking"),
        dict(id="services.nfs_shares", name="NFS Share Enumeration", category="services", default_severity="medium", description="List NFS exports accessible without authentication"),
        dict(id="services.zerologon", name="ZeroLogon (CVE-2020-1472)", category="services", default_severity="critical", cve_ids='["CVE-2020-1472"]', description="Non-destructive ZeroLogon detection via Netlogon authentication attempt with zero credentials"),
        dict(id="services.java_rmi_jmx", name="Java RMI/JMX Registry Exposed", category="services", default_severity="high", description="Detect unauthenticated Java RMI/JMX registries that allow remote code execution"),
        dict(id="services.cisco_smart_install", name="Cisco Smart Install Exposed", category="services", default_severity="high", cve_ids='["CVE-2018-0171"]', description="Detect Cisco Smart Install service exposed on port 4786 (CVE-2018-0171)"),
        dict(id="services.adb_unauth", name="ADB Unauthenticated Access", category="services", default_severity="critical", description="Detect Android Debug Bridge (ADB) exposed without authentication"),
        dict(id="services.firebird_default_creds", name="Firebird Default Credentials", category="services", default_severity="critical", description="Test Firebird database for default SYSDBA/masterkey credentials"),
        dict(id="services.ftp_cleartext", name="FTP Cleartext Protocol", category="services", default_severity="medium", description="Detect FTP services that transmit credentials without TLS encryption"),
        # Authenticated
        dict(id="authenticated.ssh_audit", name="Authenticated SSH System Audit", category="authenticated", default_severity="info", description="SSH into target and audit OS configuration and security posture", requires_auth=True),
        # Web — attack surface plugins
        dict(id="web.sqli_detect", name="SQL Injection (Error-Based)", category="web", default_severity="critical", description="Detect error-based SQL injection in URL parameters and login forms"),
        dict(id="web.xss_detect", name="Reflected XSS", category="web", default_severity="high", description="Detect reflected cross-site scripting in URL parameters"),
        dict(id="web.waf_detect", name="WAF / CDN Detection", category="web", default_severity="info", description="Detect web application firewalls and CDN proxies"),
        dict(id="web.ssrf_detect", name="SSRF Detection", category="web", default_severity="high", description="Detect server-side request forgery via common URL-valued parameters"),
        dict(id="web.broken_access_control", name="Broken Access Control", category="web", default_severity="high", description="Detect admin/management pages accessible without authentication"),
        # Network
        dict(id="network.subdomain_enum", name="Subdomain Enumeration", category="network", default_severity="info", description="Brute-force DNS subdomains for the target hostname"),
        # Phase 1 — Network fingerprints (no auth)
        dict(id="services.ms17_010_check", name="MS17-010 EternalBlue (Precise Check)", category="services", default_severity="critical", cve_ids='["CVE-2017-0144","CVE-2017-0145","CVE-2017-0146"]', description="Detect MS17-010 EternalBlue using Trans2 fingerprint technique"),
        dict(id="services.bluekeep_check", name="BlueKeep CVE-2019-0708 RDP Vulnerability", category="services", default_severity="critical", cve_ids='["CVE-2019-0708"]', description="Detect BlueKeep RDP vulnerability using MS_T120 channel probe (detection only)"),
        dict(id="services.llmnr_nbns_check", name="LLMNR/NBT-NS Poisoning Risk", category="services", default_severity="medium", description="Detect LLMNR and NetBIOS Name Service enabled — susceptible to Responder poisoning"),
        dict(id="services.memcached_unauth", name="Memcached Unauthenticated Access", category="services", default_severity="high", description="Detect Memcached instances accessible without authentication (also flags UDP amplification risk)"),
        dict(id="services.etcd_unauth", name="etcd Unauthenticated Access", category="services", default_severity="critical", description="Detect unauthenticated etcd API access exposing cluster configuration and Kubernetes secrets"),
        dict(id="services.mssql_unauth", name="MSSQL Default/Blank SA Credentials", category="services", default_severity="critical", description="Test MSSQL for default and blank SA credentials"),
        dict(id="services.mysql_unauth", name="MySQL Anonymous/Default Root Access", category="services", default_severity="critical", description="Detect MySQL with anonymous or default root access"),
        dict(id="services.postgres_unauth", name="PostgreSQL Default Credentials", category="services", default_severity="high", description="Detect PostgreSQL with default or trust-authenticated access"),
        # Phase 2 — Active Directory (require domain credentials)
        dict(id="services.dcsync_check", name="DCSync Privilege Check", category="services", default_severity="critical", description="Check if non-DC accounts have DCSync privileges (DS-Replication-Get-Changes-All)", requires_auth=True),
        dict(id="services.unconstrained_delegation", name="Kerberos Unconstrained Delegation", category="services", default_severity="high", description="Find computers with Kerberos unconstrained delegation set (TRUSTED_FOR_DELEGATION)", requires_auth=True),
        dict(id="services.gmsa_readable", name="gMSA Password Readable", category="services", default_severity="high", description="Check if gMSA (Group Managed Service Account) passwords are readable by current user", requires_auth=True),
        dict(id="services.admin_share_access", name="Local Admin via SMB Admin Shares", category="services", default_severity="high", description="Test if domain credentials grant local admin access via ADMIN$/C$ shares", requires_auth=True),
        # Phase 3 — Web detection
        dict(id="web.api_key_exposure", name="Hardcoded API Key Exposure", category="web", default_severity="critical", description="Scan HTML/JS responses for hardcoded API keys, tokens, and secrets"),
        dict(id="web.log4shell_check", name="Log4Shell CVE-2021-44228", category="web", default_severity="critical", cve_ids='["CVE-2021-44228","CVE-2021-45046"]', description="Detect Log4Shell via error-based and version-interpolation probes (no external callback required)"),
        dict(id="web.spring4shell_check", name="Spring4Shell CVE-2022-22965", category="web", default_severity="critical", cve_ids='["CVE-2022-22965"]', description="Detect Spring4Shell and exposed Spring Boot Actuator endpoints"),
        dict(id="web.exchange_autodiscover", name="Microsoft Exchange Exposed", category="web", default_severity="high", cve_ids='["CVE-2021-26855","CVE-2021-34473","CVE-2022-41082"]', description="Detect exposed Microsoft Exchange and cross-reference with ProxyLogon/ProxyShell/ProxyNotShell CVEs"),
        dict(id="web.xxe_detect", name="XML External Entity (XXE) Injection", category="web", default_severity="high", description="Detect XXE injection via error-based file read and SSRF probes on XML/SOAP endpoints"),
        # Phase 4 — OT/ICS
        dict(id="services.modbus_detect", name="Modbus Industrial Protocol Exposed", category="services", default_severity="critical", description="Detect exposed Modbus/TCP industrial control system protocol (no auth, read/write capable)"),
        dict(id="services.bacnet_detect", name="BACnet Building Automation Exposed", category="services", default_severity="high", description="Detect exposed BACnet building automation protocol via UDP Who-Is probe"),
        # Phase 5 — Cloud/Container
        dict(id="web.aws_metadata_ssrf", name="AWS IMDSv1 / Metadata SSRF", category="web", default_severity="critical", description="Check for direct IMDSv1 access and SSRF to AWS instance metadata endpoint"),
        dict(id="authenticated.docker_privileged_check", name="Privileged Container Detection", category="authenticated", default_severity="high", description="Detect privileged Docker containers via SSH inspection of Linux capabilities", requires_auth=True),
    ]

    for p in BUILTIN_PLUGINS:
        result = await session.execute(select(Plugin).where(Plugin.id == p["id"]))
        if result.scalar_one_or_none():
            continue
        plugin = Plugin(
            id=p["id"],
            name=p["name"],
            category=p["category"],
            default_severity=p["default_severity"],
            description=p.get("description"),
            cve_ids=p.get("cve_ids"),
            enabled=True,
            requires_auth=p.get("requires_auth", False),
        )
        session.add(plugin)

    await session.commit()
    logger.info("Built-in plugins seeded")


async def seed_templates(session: AsyncSession) -> None:
    """Insert system scan templates if not present."""
    import json
    from sqlalchemy import select

    SYSTEM_TEMPLATES = [
        {
            "name": "Quick Scan",
            "description": "Top 1000 ports, basic plugins only. Good for initial triage.",
            "profile_json": {
                "port_range": "top-1000",
                "plugins": ["network.*", "web.http_headers", "ssl_tls.cert_inspector", "web.sensitive_files"],
                "max_concurrent": 10,
                "timeout": 5,
            },
        },
        {
            "name": "Full Scan",
            "description": "All ports, all plugins, deeper service fingerprinting.",
            "profile_json": {
                "port_range": "1-65535",
                "plugins": ["*"],
                "max_concurrent": 5,
                "timeout": 10,
            },
        },
        {
            "name": "Web Audit",
            "description": "Focused web security audit on HTTP/HTTPS ports with all web and SSL/TLS plugins.",
            "profile_json": {
                "port_range": "80,443,8080,8443,8000,8888,3000,5000,9000",
                "plugins": ["web.*", "ssl_tls.*", "nuclei.runner"],
                "max_concurrent": 10,
                "timeout": 8,
            },
        },
        {
            "name": "Internal Network Audit",
            "description": "Comprehensive internal network scan including service plugins, database exposure, and auth bypass checks.",
            "profile_json": {
                "port_range": "top-10000",
                "plugins": ["network.*", "services.*", "ssh.*", "ssl_tls.*"],
                "max_concurrent": 8,
                "timeout": 7,
            },
        },
    ]

    for t in SYSTEM_TEMPLATES:
        result = await session.execute(
            select(ScanTemplate).where(ScanTemplate.name == t["name"], ScanTemplate.is_system == True)
        )
        if result.scalar_one_or_none():
            continue
        template = ScanTemplate(
            id=new_uuid(),
            user_id=None,
            name=t["name"],
            description=t["description"],
            profile_json=json.dumps(t["profile_json"]),
            is_system=True,
        )
        session.add(template)

    await session.commit()
    logger.info("System scan templates seeded")


async def _seed_builtin_wordlists(db: AsyncSession) -> None:
    """Create built-in wordlist records if not already present."""
    from pathlib import Path as _Path
    from scanr.models.wordlist import Wordlist as _Wordlist

    BUILTIN_DIR = _Path(__file__).parent.parent / "wordlists" / "builtin"
    WORDLIST_DIR = _Path(os.getenv("WORDLIST_DIR", "/app/wordlists")) / "builtin"
    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)

    BUILTINS = [
        ("usernames_common", "Common Usernames", "usernames", "Top 60 common service/device usernames"),
        ("passwords_common", "Common Passwords", "passwords", "Top 100 commonly used passwords"),
        ("credentials_common", "Common Credentials", "credentials", "80 common username:password pairs"),
    ]

    for slug, name, wl_type, desc in BUILTINS:
        src = BUILTIN_DIR / f"{slug}.txt"
        if not src.exists():
            continue  # file not bundled (dev environment)

        dst = WORDLIST_DIR / f"{slug}.txt"
        # Copy to volume if not there yet
        if not dst.exists():
            import shutil
            shutil.copy2(src, dst)

        # Count lines
        with open(dst, encoding="utf-8") as f:
            count = sum(1 for l in f if l.strip() and not l.startswith("#"))

        # Upsert by file path
        existing = await db.execute(
            select(_Wordlist).where(_Wordlist.file_path == str(dst))
        )
        if existing.scalar_one_or_none():
            continue

        db.add(_Wordlist(
            user_id=None,
            name=name,
            description=desc,
            type=wl_type,
            source="builtin",
            file_path=str(dst),
            entry_count=count,
            is_builtin=True,
        ))

    await db.commit()
    logger.info("Built-in wordlists seeded")
