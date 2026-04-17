from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from scanr.auth.password import hash_password
from scanr.config import get_settings
from scanr.db.session import engine
from scanr.models import Base, Plugin, User, UserRole
from scanr.models.base import new_uuid
from scanr.models.scan_template import ScanTemplate

logger = logging.getLogger(__name__)
settings = get_settings()


async def create_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")


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
