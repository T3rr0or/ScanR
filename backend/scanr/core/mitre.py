"""
MITRE ATT&CK technique mapping: plugin_id → list of technique IDs.
Format: "TXXXX" or "TXXXX.YYY" (sub-technique).
Reference: https://attack.mitre.org/
"""
from __future__ import annotations

MITRE_MAP: dict[str, list[str]] = {
    # Credential Access
    "ssh.ssh_default_creds":        ["T1110.001"],  # Brute Force: Password Guessing
    "web.default_creds_web":        ["T1110.001"],
    "services.snmp_community":      ["T1110.001"],
    "web.jwt_misconfig":            ["T1552.001"],  # Unsecured Credentials: Credentials in Files
    "services.vnc_auth":            ["T1110.001"],
    # Initial Access — Valid Default Accounts
    "services.ftp_anon":            ["T1078.001"],  # Valid Accounts: Default Accounts
    "services.redis_unauth":        ["T1078.001"],
    "services.elasticsearch_unauth":["T1078.001"],
    "services.mongodb_unauth":      ["T1078.001"],
    "services.docker_daemon_unauth":["T1078.001"],
    "services.kubernetes_api_unauth":["T1078.001"],
    "services.jupyter_unauth":      ["T1078.001"],
    # Exploitation of Remote Services / Public-Facing Apps
    "ssl_tls.heartbleed":           ["T1210", "T1190"],
    "services.smb_vulns":           ["T1210"],  # Exploitation of Remote Services
    "services.rdp_check":           ["T1210"],
    "services.ipmi_cipher_zero":    ["T1210"],
    "cve.cve_matcher":              ["T1190"],  # Exploit Public-Facing Application
    # Discovery
    "services.dns_zone_transfer":   ["T1046"],  # Network Service Discovery
    "services.netbios_info":        ["T1046"],
    "network.open_ports_info":      ["T1046"],
    "web.dir_bruteforce":           ["T1083"],  # File and Directory Discovery
    "web.dir_listing":              ["T1083"],
    "web.graphql_introspection":    ["T1046"],
    "ssl_tls.cert_inspector":       ["T1596.003"],  # Search: Digital Certificates
    # Collection / Exfiltration
    "web.sensitive_files":          ["T1552.001", "T1530"],  # Unsecured Creds + Data from Cloud Storage
    # Lateral Movement / Remote Services
    "services.smb_signing":         ["T1557.001"],  # Adversary-in-the-Middle: LLMNR/NBT-NS
    "services.smb_null_session":    ["T1135", "T1078.001"],  # Network Share Discovery + Default Accounts
    "services.smb_share_enum":      ["T1135", "T1039"],      # Network Share Discovery + Data from Shared Drive
    "services.telnet_detect":       ["T1021.004"],  # Remote Services (clear-text)
    "services.smtp_open_relay":     ["T1534"],      # Internal Spearphishing
    # Defense Evasion / Phishing support
    "web.open_redirect":            ["T1598.003"],  # Phishing for Information: Spearphishing
    "web.cors_misconfig":           ["T1185"],      # Browser Session Hijacking
    "web.clickjacking":             ["T1185"],
    # Cryptographic attacks / Sniffing
    "ssl_tls.cipher_audit":         ["T1040"],      # Network Sniffing
    "ssl_tls.protocol_check":       ["T1040"],
    "ssl_tls.poodle_beast":         ["T1040"],
    # Impact
    "services.ntp_monlist":         ["T1498.002"],  # Network DoS: Reflection Amplification
    # Active Directory / Windows enumeration
    "services.ldap_anon_bind":      ["T1087.002", "T1069.002"],  # Account Discovery + Permission Groups: Domain
    "services.ad_password_policy":  ["T1201"],      # Password Policy Discovery
    "services.rdp_info":            ["T1046", "T1018"],  # Network Service Discovery + Remote System Discovery
    "services.ike_aggressive_mode": ["T1110.002"],  # Brute Force: Password Cracking (PSK hash)
    # Information Disclosure
    "web.http_headers":             ["T1592.002"],  # Gather Victim Host Information
    "web.http_methods":             ["T1592.002"],
    "web.path_traversal":           ["T1083"],      # File and Directory Discovery
    # Multi-technique (nuclei covers many)
    "nuclei.runner":                ["T1190", "T1203"],
}

# Human-readable technique names (for display)
TECHNIQUE_NAMES: dict[str, str] = {
    "T1040":    "Network Sniffing",
    "T1046":    "Network Service Discovery",
    "T1078.001":"Valid Accounts: Default Accounts",
    "T1083":    "File & Directory Discovery",
    "T1110.001":"Brute Force: Password Guessing",
    "T1185":    "Browser Session Hijacking",
    "T1190":    "Exploit Public-Facing Application",
    "T1203":    "Exploitation for Client Execution",
    "T1210":    "Exploitation of Remote Services",
    "T1498.002":"Network DoS: Reflection Amplification",
    "T1521.004":"Remote Services (cleartext)",
    "T1530":    "Data from Cloud Storage",
    "T1534":    "Internal Spearphishing",
    "T1552.001":"Unsecured Credentials: Credentials in Files",
    "T1557.001":"Adversary-in-the-Middle",
    "T1592.002":"Gather Victim Host Information",
    "T1596.003":"Search: Digital Certificates",
    "T1598.003":"Phishing for Information",
    "T1018":    "Remote System Discovery",
    "T1021.004":"Remote Services",
    "T1021.005":"Remote Services: VNC",
    "T1033":    "System Owner/User Discovery",
    "T1039":    "Data from Network Shared Drive",
    "T1069.002":"Permission Groups Discovery: Domain Groups",
    "T1082":    "System Information Discovery",
    "T1087.002":"Account Discovery: Domain Account",
    "T1110.002":"Brute Force: Password Cracking",
    "T1110.003":"Brute Force: Password Spraying",
    "T1135":    "Network Share Discovery",
    "T1201":    "Password Policy Discovery",
    "T1595.001":"Active Scanning: Scanning IP Blocks",
    "T1649":    "Steal or Forge Authentication Certificates",
}


def mitre_tags_for_plugin(plugin_id: str) -> list[str]:
    return MITRE_MAP.get(plugin_id, [])


def technique_name(tid: str) -> str:
    return TECHNIQUE_NAMES.get(tid, tid)
