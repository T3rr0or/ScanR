from __future__ import annotations

import logging
import secrets
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

# (path, content_signature, severity, title, description)
SENSITIVE_PATHS = [
    (
        "/.git/HEAD",
        "ref: refs/heads/",
        Severity.critical,
        "Git Repository Exposed",
        "The .git directory is publicly accessible, exposing source code, credentials, and history.",
        "Restrict access to .git/ directories via web server configuration or remove from webroot.",
    ),
    (
        "/.env",
        None,
        Severity.critical,
        "Environment File Exposed (.env)",
        "The .env file is publicly accessible and may contain database passwords, API keys, and secrets.",
        "Block access to .env files in your web server configuration and never expose them publicly.",
    ),
    (
        "/.env.backup",
        None,
        Severity.critical,
        "Environment Backup File Exposed (.env.backup)",
        "A backup of the .env file is publicly accessible.",
        "Block access to backup files and remove them from the webroot.",
    ),
    (
        "/.env.local",
        None,
        Severity.critical,
        "Local Environment File Exposed (.env.local)",
        "The .env.local file is publicly accessible and may contain sensitive credentials.",
        "Block access to .env files in your web server configuration.",
    ),
    (
        "/.htpasswd",
        None,
        Severity.high,
        "HTPasswd File Exposed",
        "The .htpasswd file is publicly accessible, exposing hashed credentials.",
        "Restrict access to .htpasswd files via web server configuration.",
    ),
    (
        "/backup.sql",
        None,
        Severity.critical,
        "Database Backup Exposed (backup.sql)",
        "A SQL database backup file is publicly accessible, potentially exposing all data.",
        "Remove database backup files from the webroot. Store backups outside the document root.",
    ),
    (
        "/dump.sql",
        None,
        Severity.critical,
        "Database Dump Exposed (dump.sql)",
        "A SQL database dump is publicly accessible.",
        "Remove database dumps from the webroot.",
    ),
    (
        "/config.bak",
        None,
        Severity.high,
        "Configuration Backup File Exposed",
        "A configuration backup file is publicly accessible and may contain sensitive settings.",
        "Remove backup files from the webroot.",
    ),
    (
        "/.DS_Store",
        None,
        Severity.medium,
        "macOS .DS_Store File Exposed",
        ".DS_Store files contain directory listings and can reveal the structure of the web application.",
        "Block access to .DS_Store files and ensure they are not committed to version control.",
    ),
    (
        "/phpinfo.php",
        "PHP Version",
        Severity.medium,
        "PHPInfo Page Exposed",
        "A phpinfo() page is accessible, revealing PHP configuration, loaded modules, and environment variables.",
        "Remove phpinfo.php files from production servers.",
    ),
    (
        "/server-status",
        "Apache Server Status",
        Severity.medium,
        "Apache Server Status Exposed",
        "The Apache mod_status page is publicly accessible, revealing server internals and active requests.",
        "Restrict access to /server-status to internal IPs only.",
    ),
    (
        "/.well-known/security.txt",
        None,
        Severity.info,
        "security.txt Present",
        "A security.txt file was found at the standard location.",
        "No action required — this is a security best practice.",
    ),
]


def _matches_baseline(status_code: int, body_size: int, baselines: list[tuple[int, int]]) -> bool:
    for base_status, base_size in baselines:
        if status_code == base_status and abs(body_size - base_size) <= max(32, int(base_size * 0.03)):
            return True
    return False


class SensitiveFilesPlugin(PluginBase):
    id = "web.sensitive_files"
    name = "Sensitive File Exposure"
    description = "Check for exposed sensitive files: .git, .env, backups, phpinfo, etc."
    category = PluginCategory.web
    severity = Severity.critical
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            port_findings = await self._probe(host.ip, port.number, scheme)
            findings.extend(port_findings)
        return findings

    async def _probe(self, ip: str, port: int, scheme: str) -> list[FindingData]:
        results = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
                baselines: list[tuple[int, int]] = []
                for _ in range(2):
                    try:
                        missing = f"{scheme}://{ip}:{port}/scanr-missing-{secrets.token_hex(8)}"
                        resp = await client.get(missing)
                        baselines.append((resp.status_code, len(resp.content)))
                    except Exception:
                        pass

                for path, signature, sev, title, desc, remediation in SENSITIVE_PATHS:
                    url = f"{scheme}://{ip}:{port}{path}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code not in (200, 206):
                            continue
                        if _matches_baseline(resp.status_code, len(resp.content), baselines):
                            continue
                        if sev == Severity.info and resp.status_code == 200:
                            # Just record security.txt presence
                            results.append(FindingData(
                                plugin_id=self.id,
                                severity=sev,
                                title=title,
                                description=desc,
                                evidence=f"GET {url} → HTTP {resp.status_code}",
                                remediation=remediation,
                                port_number=port,
                                protocol="tcp",
                            ))
                            continue
                        if signature and signature not in resp.text:
                            continue
                        results.append(FindingData(
                            plugin_id=self.id,
                            severity=sev,
                            title=title,
                            description=desc,
                            evidence=f"GET {url} → HTTP {resp.status_code} ({len(resp.content)} bytes)",
                            remediation=remediation,
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                            port_number=port,
                            protocol="tcp",
                        ))
                    except Exception:
                        continue
        except Exception:
            pass
        return results
