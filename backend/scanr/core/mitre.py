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
    "services.ftp_cleartext":       ["T1040"],      # Network Sniffing (cleartext protocol)
    # Impact
    "services.ntp_monlist":         ["T1498.002"],  # Network DoS: Reflection Amplification
    # Active Directory / Windows enumeration
    "services.ldap_anon_bind":      ["T1087.002", "T1069.002"],  # Account Discovery + Permission Groups: Domain
    "services.ad_password_policy":  ["T1201"],      # Password Policy Discovery
    "services.rdp_info":            ["T1046", "T1018"],  # Network Service Discovery + Remote System Discovery
    "services.ike_aggressive_mode": ["T1110.002"],  # Brute Force: Password Cracking (PSK hash)
    "services.zerologon":           ["T1210", "T1649"],  # Exploitation of Remote Services + Forge Certs
    "services.nfs_shares":          ["T1135", "T1039"],  # Network Share Discovery + Data from Shared Drive
    "services.java_rmi_jmx":        ["T1203"],      # Exploitation for Client Execution
    "services.cisco_smart_install": ["T1190", "T1565.001"],  # Exploit Public App + Stored Data Manipulation
    "services.adb_unauth":          ["T1219", "T1078.001"],  # Remote Access Software + Default Accounts
    "services.firebird_default_creds": ["T1078.001"],  # Valid Accounts: Default Accounts
    # Information Disclosure
    "web.http_headers":             ["T1592.002"],  # Gather Victim Host Information
    "web.http_methods":             ["T1592.002"],
    "web.path_traversal":           ["T1083"],      # File and Directory Discovery
    # Multi-technique (nuclei covers many)
    "nuclei.runner":                ["T1190", "T1203"],
    # Authenticated checks
    "authenticated.ssh_audit":      ["T1078.001", "T1552.001", "T1201"],
    # New coverage plugins
    "network.open_resolver":            ["T1498.002"],  # Reflection Amplification
    "services.udp_amplification":       ["T1498.002"],
    "services.dns_dynamic_update":      ["T1584.002", "T1565.001"],  # Compromise Infra: DNS + Data Manip
    "services.vpn_appliance_exposure":  ["T1133", "T1190"],  # External Remote Services + Exploit Public App
    "services.devops_platform_exposure":["T1195.002", "T1078.001"],  # Supply Chain: Software + Default Accounts
    "services.db_extended_unauth":      ["T1078.001", "T1530"],  # Default Accounts + Data from Cloud Storage
    "services.rtsp_exposure":           ["T1125"],       # Video Capture
    "services.printer_exposure":        ["T1200", "T1552.001"],  # Hardware Additions + Creds in Files
    "services.iscsi_exposure":          ["T1200", "T1039"],  # Hardware Additions + Data from Network Share
    "services.grpc_reflection":         ["T1046"],       # Network Service Discovery
    "services.smtp_smuggling":          ["T1534", "T1656"],  # Internal Spearphishing + Impersonation
    "services.ldap_anon_write":         ["T1098", "T1136.002"],  # Account Manipulation + Create Domain Account
    "ssh.terrapin":                     ["T1557", "T1040"],  # Adversary-in-the-Middle + Network Sniffing
    "ssl_tls.handshake_hardening":      ["T1040", "T1557"],
    "ssl_tls.ticketbleed":              ["T1040", "T1552.004"],  # Sniffing + Private Keys
    "ssl_tls.ct_log_exposure":          ["T1596.003", "T1590.002"],  # Digital Certificates + DNS
    "web.source_map_exposure":          ["T1592.002", "T1552.001"],  # Host Info + Creds in Files
    "web.aspnet_viewstate":             ["T1190", "T1552.001"],  # Exploit Public App + Creds in Files
    "web.ntlm_endpoint_disclosure":     ["T1590.002", "T1592.002"],  # Gather Victim DNS + Host Info
    "web.websocket_security":           ["T1185"],       # Browser Session Hijacking
    "web.cache_deception":              ["T1539", "T1185"],  # Steal Web Session Cookie + Session Hijack
    "authenticated.windows_patch_status": ["T1210", "T1082"],  # Exploit Remote Services + System Info
    "authenticated.windows_local_privesc":["T1548.002", "T1574.009", "T1003.001"],  # Bypass UAC + Unquoted Path + LSASS
    "authenticated.laps_status":        ["T1078.003", "T1550.002"],  # Local Accounts + Pass the Hash
    "authenticated.windows_defenses":   ["T1562.001", "T1003.001"],  # Impair Defenses + LSASS Memory
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
    "T1219":    "Remote Access Software",
    "T1565.001":"Stored Data Manipulation",
    "T1595.001":"Active Scanning: Scanning IP Blocks",
    "T1649":    "Steal or Forge Authentication Certificates",
    "T1098":    "Account Manipulation",
    "T1125":    "Video Capture",
    "T1133":    "External Remote Services",
    "T1136.002":"Create Account: Domain Account",
    "T1195.002":"Supply Chain Compromise: Software",
    "T1200":    "Hardware Additions",
    "T1539":    "Steal Web Session Cookie",
    "T1548.002":"Abuse Elevation Control: Bypass UAC",
    "T1550.002":"Use Alternate Auth Material: Pass the Hash",
    "T1552.004":"Unsecured Credentials: Private Keys",
    "T1557":    "Adversary-in-the-Middle",
    "T1562.001":"Impair Defenses: Disable or Modify Tools",
    "T1574.009":"Hijack Execution Flow: Unquoted Path",
    "T1584.002":"Compromise Infrastructure: DNS Server",
    "T1590.002":"Gather Victim Network Information: DNS",
    "T1656":    "Impersonation",
    "T1003.001":"OS Credential Dumping: LSASS Memory",
    "T1078.003":"Valid Accounts: Local Accounts",
}


def mitre_tags_for_plugin(plugin_id: str) -> list[str]:
    return MITRE_MAP.get(plugin_id, [])


def technique_name(tid: str) -> str:
    return TECHNIQUE_NAMES.get(tid, tid)
