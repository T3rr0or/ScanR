from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

# Common paths wordlist (200 entries, no external dependency needed)
COMMON_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "pma", "mysql", "adminer", "dbadmin",
    "api", "api/v1", "api/v2", "api/v3",
    "swagger", "swagger-ui", "swagger-ui.html", "api-docs",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "health", "status", "metrics", "info",
    "console", "h2-console", "jmx-console", "web-console",
    "manager", "management", "tomcat", "jboss",
    "jenkins", "gitlab", "bitbucket", "sonar", "grafana", "kibana",
    "setup", "install", "installer", "setup.php",
    "config", "configuration", "settings",
    "backup", "backups", "bak",
    "old", "archive", "archives", "temp", "tmp",
    "test", "testing", "debug", "dev", "development",
    "staging", "qa",
    "upload", "uploads", "files", "file", "media",
    "images", "img", "assets", "static",
    "js", "css", "fonts",
    "robots.txt", "sitemap.xml", "sitemap.txt",
    ".well-known", ".well-known/security.txt", ".well-known/change-password",
    "humans.txt", "security.txt",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "readme", "README", "readme.txt", "readme.md",
    "changelog", "CHANGELOG", "license", "LICENSE",
    "docs", "doc", "documentation", "help",
    "portal", "dashboard", "panel",
    "user", "users", "account", "accounts", "profile",
    "register", "signup", "signin", "logout", "auth",
    "oauth", "oauth2", "sso", "saml", "openid",
    "forgot", "reset", "password",
    "search", "query",
    "download", "downloads", "export",
    "import", "migrate", "migration",
    "cron", "scheduler",
    "log", "logs", "error_log", "access_log",
    "wp-content", "wp-includes",
    "index.php", "index.html", "index.asp", "index.aspx", "index.jsp",
    "default.asp", "default.aspx", "home.php",
    "server-info", "server-status",
    ".git", ".svn", ".hg", ".bzr",
    ".env", ".env.local", ".env.backup",
    ".htaccess", ".htpasswd",
    "web.config", "web.config.bak",
    "phpinfo.php", "info.php", "php.php",
    "shell.php", "c99.php", "r57.php", "webshell.php",
    "cgi-bin", "cgi",
    "bin", "scripts",
    "error", "errors", "404", "500",
    "xmlrpc.php", "wp-cron.php",
    "joomla", "drupal", "magento",
    "app", "application",
    "site", "portal", "intranet",
    "vpn", "remote", "rdp",
    "mail", "email", "webmail", "roundcube", "squirrelmail",
    "ftp", "sftp",
    "monitoring", "nagios", "zabbix", "prometheus",
    "elastic", "elasticsearch", "solr",
    "redis", "memcache", "mongo",
    "db", "database",
    "aws", "azure", "gcp", "cloud",
    "kubernetes", "k8s", "docker",
    "api-gateway", "gateway",
    "proxy", "nginx", "apache",
    "certs", "ssl", "tls",
    "tokens", "keys", "secrets",
    "payment", "checkout", "cart",
    "invoice", "billing", "order",
    "report", "reports", "analytics",
    "dashboard/login", "admin/login",
    "manage", "mgmt",
    "backend", "frontend",
    "internal", "private",
    "secure", "security",
    "vendor", "lib", "library",
    "node_modules",
    "Makefile", "Dockerfile", "docker-compose.yml",
    "requirements.txt", "package.json", "composer.json",
    "Gemfile", "pom.xml", "build.gradle",
    ".travis.yml", ".github", ".circleci",
]

MANAGEMENT_INDICATORS = [
    "actuator", "h2-console", "jmx-console", "web-console",
    "manager", "management", "jenkins", "grafana", "kibana",
    "console", "admin", "administrator", "phpmyadmin", "adminer",
    "wp-admin",
]


class DirBruteforcePlugin(PluginBase):
    id = "web.dir_bruteforce"
    name = "Directory Bruteforce"
    description = "Enumerate common HTTP paths to discover hidden endpoints and admin panels"
    category = PluginCategory.web
    severity = Severity.info
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            port_findings = await self._scan(host.ip, port.number, scheme)
            findings.extend(port_findings)
        return findings

    async def _scan(self, ip: str, port: int, scheme: str) -> list[FindingData]:
        base = f"{scheme}://{ip}:{port}/"
        found: list[tuple[str, int, int]] = []  # (path, status, size)
        sem = asyncio.Semaphore(20)

        async def probe(path: str) -> None:
            url = base + path.lstrip("/")
            try:
                async with sem:
                    async with httpx.AsyncClient(verify=False, timeout=4.0, follow_redirects=False) as client:
                        resp = await client.get(url)
                        if resp.status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403):
                            found.append((path, resp.status_code, len(resp.content)))
            except Exception:
                pass

        await asyncio.gather(*[probe(p) for p in COMMON_PATHS])

        findings = []
        for path, status, size in found:
            is_mgmt = any(ind in path for ind in MANAGEMENT_INDICATORS)
            sev = Severity.medium if is_mgmt else Severity.info
            auth_note = ""
            if status in (401, 403):
                sev = Severity.info
                auth_note = " (requires authentication)"

            findings.append(FindingData(
                plugin_id=self.id,
                severity=sev,
                title=f"Path Found: /{path}" + (" (Management Interface)" if is_mgmt else ""),
                description=(
                    f"The path '/{path}' exists on the web server{auth_note}. "
                    + ("This appears to be a management or admin interface." if is_mgmt else "")
                ),
                evidence=f"GET {base}{path} → HTTP {status} ({size} bytes)",
                remediation=(
                    "Review whether this path should be publicly accessible. "
                    "Restrict management interfaces to internal networks or require authentication."
                ) if is_mgmt else "Verify whether this resource should be publicly accessible.",
                port_number=port,
                protocol="tcp",
            ))
        return findings
