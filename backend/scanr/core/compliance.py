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
}


def tags_for_plugin(plugin_id: str) -> list[str]:
    return COMPLIANCE_MAP.get(plugin_id, [])
