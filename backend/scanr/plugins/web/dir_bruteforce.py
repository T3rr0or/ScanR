from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

_SECLISTS_BASE = Path("/usr/share/seclists/Discovery/Web-Content")
_WORDLIST_SMALL  = _SECLISTS_BASE / "common.txt"          # ~4600 entries
_WORDLIST_MEDIUM = _SECLISTS_BASE / "big.txt"             # ~20k entries
_WORDLIST_LARGE  = _SECLISTS_BASE / "directory-list-2.3-medium.txt"  # ~220k entries


def _load_wordlist(path: Path) -> list[str]:
    try:
        lines = path.read_text(errors="ignore").splitlines()
        return [l.strip().lstrip("/") for l in lines if l.strip() and not l.startswith("#")]
    except Exception:
        return []


# Fallback embedded wordlist (used when SecLists not available)
COMMON_PATHS = [
    "admin", "admin.php", "administrator", "administrator.php",
    "login", "login.php", "login2.php", "wp-admin", "wp-login.php",
    "admindash.php", "admin_dashboard.php", "dashboard.php",
    "phpmyadmin", "pma", "mysql", "adminer", "dbadmin",
    "user.php", "users.php", "profile.php", "account.php",
    "panel.php", "control.php", "manage.php", "portal.php",
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
    "console", "admin", "admin.php", "administrator", "administrator.php",
    "admindash", "admindash.php", "phpmyadmin", "adminer",
    "dashboard", "dashboard.php", "panel", "panel.php", "wp-admin",
]


class DirBruteforcePlugin(PluginBase):
    id = "web.dir_bruteforce"
    name = "Directory Bruteforce"
    description = "Enumerate common HTTP paths to discover hidden endpoints and admin panels"
    category = PluginCategory.web
    severity = Severity.info
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        profile = getattr(context, "profile", "standard")
        wordlist = self._pick_wordlist(profile)
        findings = []
        for port in host.ports:
            if port.number not in HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            port_findings = await self._scan(host.ip, port.number, scheme, wordlist)
            findings.extend(port_findings)
        return findings

    def _pick_wordlist(self, profile: str) -> list[str]:
        if profile == "full" and _WORDLIST_LARGE.exists():
            paths = _load_wordlist(_WORDLIST_LARGE)
            logger.debug("dir_bruteforce: using large SecLists wordlist (%d entries)", len(paths))
            return paths
        if profile in ("standard", "full") and _WORDLIST_MEDIUM.exists():
            paths = _load_wordlist(_WORDLIST_MEDIUM)
            logger.debug("dir_bruteforce: using medium SecLists wordlist (%d entries)", len(paths))
            return paths
        if _WORDLIST_SMALL.exists():
            paths = _load_wordlist(_WORDLIST_SMALL)
            logger.debug("dir_bruteforce: using small SecLists wordlist (%d entries)", len(paths))
            return paths
        logger.debug("dir_bruteforce: SecLists not found, using embedded wordlist")
        return COMMON_PATHS

    async def _scan(self, ip: str, port: int, scheme: str, wordlist: list[str]) -> list[FindingData]:
        base = f"{scheme}://{ip}:{port}/"
        found: list[tuple[str, int, int]] = []  # (path, status, size)
        sem = asyncio.Semaphore(20)

        async with httpx.AsyncClient(
            verify=False, timeout=4.0, follow_redirects=False,
            limits=httpx.Limits(max_connections=30, max_keepalive_connections=20),
        ) as client:
            async def probe(path: str) -> None:
                url = base + path.lstrip("/")
                try:
                    async with sem:
                        resp = await client.get(url)
                        if resp.status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403):
                            found.append((path, resp.status_code, len(resp.content)))
                except Exception:
                    pass

            await asyncio.gather(*[probe(p) for p in wordlist])

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
