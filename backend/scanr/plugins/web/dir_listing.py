"""Directory listing detection plugin.

Checks whether web server directory listing is enabled by looking for
common index page signatures in responses to directory-like URLs.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)
HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

# Signatures that indicate a directory listing page
_LISTING_SIGS = [
    b"Index of /",
    b"Directory listing for /",
    b"<title>Directory listing",
    b"Parent Directory</a>",
    b'href="?C=N&amp;O=D"',   # Apache sort links
    b"[To Parent Directory]",  # IIS
]

_CHECK_PATHS = ["/", "/images/", "/static/", "/assets/", "/uploads/", "/files/"]


class DirListingPlugin(PluginBase):
    id = "web.dir_listing"
    name = "Directory Listing Enabled"
    description = "Detect web server directory listing on common paths"
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        checked: set[int] = set()
        for port in host.ports:
            if not is_web_port(port) or port.number in checked:
                continue
            checked.add(port.number)
            scheme = web_scheme(port)
            base = f"{scheme}://{host.ip}:{port.number}"
            listed_paths = await self._find_listings(context, base)
            if listed_paths:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Directory Listing Enabled",
                    description=(
                        "The web server returns directory listings for one or more paths. "
                        "This exposes file and directory names to unauthenticated visitors and "
                        "may reveal sensitive files, backup files, or application structure."
                    ),
                    evidence="Directory listing detected at: " + ", ".join(listed_paths),
                    remediation=(
                        "Disable directory listing in your web server config. "
                        "Apache: 'Options -Indexes'. Nginx: remove 'autoindex on'."
                    ),
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _find_listings(self, context, base: str) -> list[str]:
        found = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False,
                **context.proxy_config()
            ) as client:
                for path in _CHECK_PATHS:
                    try:
                        resp = await client.get(base + path)
                        if resp.status_code == 200:
                            body = resp.content[:8192]
                            if any(sig in body for sig in _LISTING_SIGS):
                                found.append(base + path)
                    except Exception:
                        continue
        except Exception:
            pass
        return found
