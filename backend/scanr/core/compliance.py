"""
Static compliance control mapping: plugin_id → list of control tags.
Tags format: "FRAMEWORK:CONTROL-ID"
"""
from __future__ import annotations

COMPLIANCE_MAP: dict[str, list[str]] = {
    # SSL/TLS
    "ssl_tls.cert_inspector": [
        "PCI-DSS:4.2.1", "PCI-DSS:12.3.3",
        "ISO27001:A.8.24",
        "CIS:18.5",
    ],
    "ssl_tls.cipher_audit": [
        "PCI-DSS:4.2.1",
        "ISO27001:A.8.24",
        "CIS:18.5",
        "NIST:SC-8",
    ],
    "ssl_tls.protocol_check": [
        "PCI-DSS:4.2.1",
        "ISO27001:A.8.24",
        "CIS:18.5",
        "NIST:SC-8",
    ],
    "ssl_tls.heartbleed": [
        "PCI-DSS:6.3.3",
        "ISO27001:A.8.8",
        "CIS:7.4",
        "NIST:SI-2",
    ],
    "ssl_tls.poodle_beast": [
        "PCI-DSS:6.3.3",
        "ISO27001:A.8.8",
        "CIS:7.4",
    ],
    # Web
    "web.http_headers": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
        "CIS:16.10",
        "NIST:SI-10",
    ],
    "web.http_methods": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
        "CIS:4.8",
    ],
    "web.cors_misconfig": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
        "CIS:16.10",
    ],
    "web.clickjacking": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
    ],
    "web.dir_listing": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
        "CIS:4.8",
    ],
    "web.default_creds_web": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:5.2",
        "NIST:IA-5",
    ],
    "web.open_redirect": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
        "CIS:16.1",
    ],
    "web.path_traversal": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
        "CIS:18.3",
        "NIST:SI-10",
    ],
    "web.jwt_misconfig": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.5",
        "CIS:16.8",
        "NIST:IA-8",
    ],
    "web.sensitive_files": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
        "CIS:4.8",
    ],
    "web.dir_bruteforce": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
    ],
    # Services
    "services.ftp_anon": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.20",
        "CIS:4.8",
        "NIST:AC-3",
    ],
    "services.smtp_open_relay": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.20",
        "CIS:9.3",
    ],
    "services.snmp_community": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:12.1",
        "NIST:IA-5",
    ],
    "services.rdp_check": [
        "PCI-DSS:6.3.3",
        "ISO27001:A.8.8",
        "CIS:7.4",
        "NIST:SI-2",
    ],
    "services.smb_signing": [
        "PCI-DSS:4.2.1",
        "ISO27001:A.8.24",
        "CIS:9.1",
    ],
    "services.smb_vulns": [
        "PCI-DSS:6.3.3",
        "ISO27001:A.8.8",
        "CIS:7.4",
        "NIST:SI-2",
    ],
    "services.telnet_detect": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.20",
        "CIS:4.8",
        "NIST:CM-7",
    ],
    "services.vnc_auth": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:5.2",
    ],
    "services.dns_zone_transfer": [
        "PCI-DSS:6.4.1",
        "ISO27001:A.8.9",
        "CIS:9.3",
    ],
    "services.redis_unauth": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:4.6",
        "NIST:AC-3",
    ],
    "services.elasticsearch_unauth": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:4.6",
        "NIST:AC-3",
    ],
    "services.mongodb_unauth": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:4.6",
        "NIST:AC-3",
    ],
    "services.docker_daemon_unauth": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:4.6",
        "NIST:AC-3",
    ],
    "services.kubernetes_api_unauth": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:4.6",
        "NIST:AC-3",
    ],
    "services.jupyter_unauth": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:4.6",
    ],
    "services.ipmi_cipher_zero": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:4.6",
        "NIST:IA-5",
    ],
    # SSH
    "ssh.ssh_algos": [
        "PCI-DSS:4.2.1",
        "ISO27001:A.8.24",
        "CIS:18.5",
    ],
    "ssh.ssh_version": [
        "PCI-DSS:6.3.3",
        "ISO27001:A.8.8",
        "CIS:7.4",
    ],
    "ssh.ssh_default_creds": [
        "PCI-DSS:2.2.1",
        "ISO27001:A.8.5",
        "CIS:5.2",
        "NIST:IA-5",
    ],
    # Authenticated
    "authenticated.ssh_audit": [
        "PCI-DSS:2.2.1", "ISO27001:A.8.5", "CIS:5.2", "NIST:CM-7",
    ],
    # New service plugins
    "services.smb_null_session": [
        "PCI-DSS:2.2.1", "ISO27001:A.8.20", "CIS:9.1",
    ],
    "services.smb_share_enum": [
        "PCI-DSS:7.1.1", "ISO27001:A.8.3", "CIS:3.3",
    ],
    "services.ldap_anon_bind": [
        "PCI-DSS:2.2.1", "ISO27001:A.8.5", "CIS:16.2", "NIST:AC-3",
    ],
    "services.ad_password_policy": [
        "PCI-DSS:8.3.6", "ISO27001:A.8.5", "CIS:5.2", "NIST:IA-5",
    ],
    "services.rdp_info": [
        "PCI-DSS:2.2.7", "ISO27001:A.8.20",
    ],
    "services.ike_aggressive_mode": [
        "PCI-DSS:4.2.1", "ISO27001:A.8.24", "CIS:12.6", "NIST:SC-8",
    ],
    "services.nfs_shares": [
        "PCI-DSS:7.1.1", "ISO27001:A.8.3", "CIS:3.3", "NIST:AC-3",
    ],
    "services.zerologon": [
        "PCI-DSS:6.3.3", "ISO27001:A.8.8", "CIS:7.4", "NIST:SI-2",
    ],
    "services.java_rmi_jmx": [
        "PCI-DSS:2.2.1", "ISO27001:A.8.20", "CIS:4.8", "NIST:CM-7",
    ],
    "services.cisco_smart_install": [
        "PCI-DSS:6.3.3", "ISO27001:A.8.8", "CIS:7.4", "NIST:SI-2",
    ],
    "services.adb_unauth": [
        "PCI-DSS:2.2.1", "ISO27001:A.8.5", "CIS:4.6", "NIST:AC-3",
    ],
    "services.firebird_default_creds": [
        "PCI-DSS:2.2.1", "ISO27001:A.8.5", "CIS:5.2", "NIST:IA-5",
    ],
    "services.ftp_cleartext": [
        "PCI-DSS:4.2.1", "ISO27001:A.8.24", "CIS:4.8", "NIST:SC-8",
    ],
    # Web attack surface
    "web.sqli_detect": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9", "CIS:16.1", "NIST:SI-10",
    ],
    "web.xss_detect": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9", "CIS:16.1", "NIST:SI-10",
    ],
    "web.waf_detect": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9",
    ],
    "web.ssrf_detect": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9", "CIS:16.1", "NIST:SI-10",
    ],
    "web.broken_access_control": [
        "PCI-DSS:7.1.1", "ISO27001:A.8.3", "CIS:6.1", "NIST:AC-3",
    ],
    "web.graphql_introspection": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9",
    ],
    # Network
    "network.subdomain_enum": [
        "ISO27001:A.8.9", "CIS:4.8",
    ],
    # Authenticated AD
    "services.kerberoastable": [
        "PCI-DSS:8.3.6", "ISO27001:A.8.5", "CIS:5.4", "NIST:IA-5",
    ],
    "services.asreproastable": [
        "PCI-DSS:8.3.6", "ISO27001:A.8.5", "CIS:5.4", "NIST:IA-5",
    ],
    "services.dcsync_check": [
        "PCI-DSS:7.1.1", "ISO27001:A.8.3", "CIS:5.4", "NIST:AC-6",
    ],
    "services.unconstrained_delegation": [
        "PCI-DSS:7.1.1", "ISO27001:A.8.3", "CIS:5.4", "NIST:AC-6",
    ],
    "services.gmsa_readable": [
        "PCI-DSS:8.3.6", "ISO27001:A.8.5", "CIS:5.4", "NIST:IA-5",
    ],
    # New plugins
    "web.sqli_blind": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9", "CIS:16.1", "NIST:SI-10",
    ],
    "web.ssti_detect": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9", "CIS:16.1", "NIST:SI-10",
    ],
    "web.http_smuggling": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9", "CIS:16.1",
    ],
    "web.deserial_probe": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9", "CIS:16.1", "NIST:SI-10",
    ],
    "services.printnightmare": [
        "PCI-DSS:6.3.3", "ISO27001:A.8.8", "CIS:7.4", "NIST:SI-2",
    ],
    "services.ntlmrelay_opportunity": [
        "PCI-DSS:4.2.1", "ISO27001:A.8.24", "CIS:9.1", "NIST:IA-8",
    ],
    "services.k8s_rbac_enum": [
        "PCI-DSS:7.1.1", "ISO27001:A.8.3", "CIS:5.4", "NIST:AC-6",
    ],
    "web.cloud_ssrf": [
        "PCI-DSS:6.4.1", "ISO27001:A.8.9", "CIS:16.1",
    ],
    "network.subdomain_takeover": [
        "ISO27001:A.8.9", "CIS:4.8", "NIST:CM-8",
    ],
}


def tags_for_plugin(plugin_id: str) -> list[str]:
    return COMPLIANCE_MAP.get(plugin_id, [])
