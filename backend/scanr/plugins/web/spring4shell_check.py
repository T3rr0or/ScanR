"""Spring4Shell detection.

Detects CVE-2022-22965 (Spring4Shell) via class.module.classLoader binding probes
and checks for exposed Spring Boot Actuator endpoints.
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

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000]


class Spring4ShellCheckPlugin(PluginBase):
    id = "web.spring4shell_check"
    name = "Spring4Shell Detection"
    description = "Detect Spring4Shell (CVE-2022-22965) and exposed Spring Boot Actuator endpoints"
    category = PluginCategory.web
    severity = Severity.critical
    cve_ids = ["CVE-2022-22965"]
    cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            results = await self._probe(base_url, port.number)
            findings.extend(results)
        return findings

    async def _probe(self, base_url: str, port: int) -> list[FindingData]:
        findings: list[FindingData] = []

        async with httpx.AsyncClient(
            verify=False, timeout=8.0, follow_redirects=True,
                **context.proxy_config()
            ) as client:
            # Check for actuator endpoints (independent of Spring4Shell)
            actuator_findings = await self._check_actuator(client, base_url, port)
            findings.extend(actuator_findings)

            # Detect Spring
            is_spring = await self._detect_spring(client, base_url)

            if is_spring:
                result = await self._probe_spring4shell(client, base_url, port)
                if result:
                    findings.append(result)

        return findings

    async def _detect_spring(self, client: httpx.AsyncClient, base_url: str) -> bool:
        try:
            resp = await client.get(f"{base_url}/nonexistent-path-404")
            headers = dict(resp.headers)
            if "x-application-context" in headers:
                return True
            if "Whitelabel Error Page" in resp.text or "Spring Boot" in resp.text:
                return True
            if (
                "application/json" in headers.get("content-type", "")
                and "timestamp" in resp.text
                and "status" in resp.text
            ):
                return True  # Spring error response format
        except Exception:
            pass
        return False

    async def _probe_spring4shell(
        self, client: httpx.AsyncClient, base_url: str, port: int
    ) -> FindingData | None:
        payload = {
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "ScanRProbe",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
        }
        endpoints = ["/", "/login", "/api", "/upload", "/rest/api/v1"]

        for endpoint in endpoints:
            try:
                resp = await client.post(f"{base_url}{endpoint}", data=payload)
                if resp.status_code == 400:
                    body = resp.text
                    # Spring error response format distinguishes from generic 400
                    if '"status":400' in body and '"error"' in body and "timestamp" in body:
                        return FindingData(
                            plugin_id=self.id,
                            severity=Severity.critical,
                            title="Spring4Shell CVE-2022-22965 — Vulnerable Spring Application Detected",
                            description=(
                                "A Spring Framework application was detected and responded to the Spring4Shell probe. "
                                "CVE-2022-22965 allows RCE via data binding when running on JDK 9+ with a WAR deployment. "
                                "An attacker can upload a JSP web shell by manipulating class.module.classLoader parameters."
                            ),
                            evidence=(
                                f"POST {base_url}{endpoint} with classLoader binding returned Spring-format 400 error.\n"
                                f"Response snippet: {body[:300]}"
                            ),
                            remediation=(
                                "Upgrade Spring Framework to 5.3.18+, 5.2.20+, or Spring Boot to 2.6.6+, 2.5.12+. "
                                "As a workaround, bind disallowedFields=class.* in WebDataBinder."
                            ),
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                                "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
                            ],
                            cve_ids=self.cve_ids,
                            cvss_vector=self.cvss_vector,
                            port_number=port,
                            protocol="tcp",
                        )
            except Exception:
                pass

        return None

    async def _check_actuator(
        self, client: httpx.AsyncClient, base_url: str, port: int
    ) -> list[FindingData]:
        findings: list[FindingData] = []

        # /actuator/env — may expose environment variables and secrets
        try:
            resp = await client.get(f"{base_url}/actuator/env")
            if resp.status_code == 200 and (
                "propertySources" in resp.text or "activeProfiles" in resp.text
            ):
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.medium,
                    title="Spring Boot Actuator /env Exposed",
                    description=(
                        f"Spring Boot Actuator /env endpoint at {base_url}/actuator/env is publicly accessible. "
                        "It exposes environment variables, application properties, and may reveal credentials or API keys."
                    ),
                    evidence=(
                        f"GET /actuator/env → {resp.status_code} ({len(resp.text)} bytes)\n"
                        f"Preview: {resp.text[:300]}"
                    ),
                    remediation=(
                        "Disable or restrict actuator endpoints. In application.properties: "
                        "management.endpoints.web.exposure.include=health,info (exclude env, heapdump, beans). "
                        "Require authentication for actuator endpoints."
                    ),
                    references=[
                        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"
                    ],
                    port_number=port,
                    protocol="tcp",
                ))
        except Exception:
            pass

        # /actuator/heapdump — CRITICAL: heap dump contains full JVM memory including secrets
        try:
            resp = await client.get(f"{base_url}/actuator/heapdump", timeout=5.0)
            content_type = resp.headers.get("content-type", "").lower()
            body_start = resp.content[:32].lstrip()
            looks_like_heapdump = (
                not resp.history
                and resp.status_code == 200
                and len(resp.content) > 1000
                and not body_start.startswith((b"<!doctype html", b"<html"))
                and (
                    resp.content.startswith(b"JAVA PROFILE")
                    or "application/octet-stream" in content_type
                    or "application/x-hprof" in content_type
                    or "application/vnd.spring-boot.actuator" in content_type
                )
            )
            if looks_like_heapdump:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="Spring Boot Actuator /heapdump Exposed",
                    description=(
                        f"Spring Boot Actuator /heapdump at {base_url}/actuator/heapdump is publicly accessible. "
                        "Heap dumps contain the full JVM memory including plaintext passwords, session tokens, "
                        "database credentials, and encryption keys."
                    ),
                    evidence=(
                        f"GET /actuator/heapdump → {resp.status_code} "
                        f"({len(resp.content) // 1024}KB response)"
                    ),
                    remediation=(
                        "Disable heapdump endpoint immediately: management.endpoints.web.exposure.include=health. "
                        "Require authentication for all actuator endpoints. "
                        "Rotate all credentials as they may be compromised."
                    ),
                    references=[
                        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"
                    ],
                    port_number=port,
                    protocol="tcp",
                ))
        except Exception:
            pass

        return findings
