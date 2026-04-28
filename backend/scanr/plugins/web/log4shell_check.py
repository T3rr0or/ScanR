"""Log4Shell detection.

Detects CVE-2021-44228 via error-based and version-interpolation probes
injected into common HTTP headers. No external DNS callback required.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000]

_INJECT_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "X-Api-Version",
    "Referer",
    "X-Requested-With",
]

# Version interpolation payload — reveals Java version string if Log4j processes it
_VERSION_PAYLOAD = "${java:version}"

# Obfuscated JNDI payload — triggers error if processed but JNDI connection fails
# 127.0.0.1:1099 is the scanner's own loopback — if Log4j processes this payload it
# will attempt an outbound RMI lookup back to itself, which fails harmlessly.
# Using loopback avoids external JNDI callbacks while still triggering the
# "JNDI connection refused" error signature that vulnerable Log4j versions emit.
_JNDI_PAYLOAD = "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1:1099/x}"

_LOG4J_SIGNATURES = [
    re.compile(r"log4j", re.I),
    re.compile(r"org\.apache\.logging", re.I),
    re.compile(r"JndiManager", re.I),
    re.compile(r"JNDI.*exception", re.I),
    re.compile(r"NamingException", re.I),
]

_JAVA_VERSION_RE = re.compile(
    r"Java version \d+\.\d+|Java \d+\.\d+\.\d+|jdk[\d_]+", re.I
)


class Log4ShellCheckPlugin(PluginBase):
    id = "web.log4shell_check"
    name = "Log4Shell Detection"
    description = "Detect Log4Shell (CVE-2021-44228) via error-based and version-interpolation probes"
    category = PluginCategory.web
    severity = Severity.critical
    cve_ids = ["CVE-2021-44228", "CVE-2021-45046"]
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in HTTP_PORTS or port.state != "open":
                continue
            scheme = "https" if port.number in (443, 8443) else "http"
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._probe(base_url, port.number)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, base_url: str, port: int) -> FindingData | None:
        endpoints = ["/", "/login", "/api", "/search", "/api/v1/search"]

        async with httpx.AsyncClient(
            verify=False, timeout=8.0, follow_redirects=True
        ) as client:
            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"

                # Technique 1: version interpolation
                try:
                    headers = {"User-Agent": f"ScanR-probe {_VERSION_PAYLOAD}"}
                    resp = await client.get(url, headers=headers)
                    m = _JAVA_VERSION_RE.search(resp.text)
                    if m:
                        return self._finding(
                            base_url, port, url,
                            f"Java version string interpolated in response: {m.group()}",
                        )
                except Exception:
                    pass

                # Technique 2: inject JNDI payload in multiple headers, check for stack trace
                try:
                    inject_headers = {h: _JNDI_PAYLOAD for h in _INJECT_HEADERS}
                    inject_headers["User-Agent"] = f"Mozilla/5.0 {_JNDI_PAYLOAD}"
                    resp = await client.get(url, headers=inject_headers)
                    for sig in _LOG4J_SIGNATURES:
                        if sig.search(resp.text):
                            return self._finding(
                                base_url, port, url,
                                f"log4j signature detected in error response: {sig.pattern}",
                            )
                except Exception:
                    pass

        return None

    def _finding(self, base_url: str, port: int, url: str, evidence: str) -> FindingData:
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="Log4Shell CVE-2021-44228 — JNDI Interpolation Detected",
            description=(
                "The application appears to use Log4j and may be vulnerable to Log4Shell (CVE-2021-44228). "
                "JNDI lookup interpolation was detected in HTTP responses. "
                "An attacker can achieve Remote Code Execution by triggering JNDI lookups to a malicious LDAP server."
            ),
            evidence=f"URL: {url}\n{evidence}",
            remediation=(
                "Upgrade Log4j to 2.17.1+ (Java 8), 2.12.4+ (Java 7), or 2.3.2+ (Java 6). "
                "If upgrade is not immediately possible: set log4j2.formatMsgNoLookups=true or "
                "remove the JndiLookup class: zip -q -d log4j-core-*.jar "
                "org/apache/logging/log4j/core/lookup/JndiLookup.class"
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://logging.apache.org/log4j/2.x/security.html",
            ],
            cve_ids=self.cve_ids,
            cvss_vector=self.cvss_vector,
            port_number=port,
            protocol="tcp",
        )
