"""Microsoft Exchange exposure detection.

Detects exposed Exchange services and cross-references with known critical CVEs
including ProxyLogon, ProxyShell, and ProxyNotShell.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_EXCHANGE_PORTS = [80, 443]

_EXCHANGE_ENDPOINTS = [
    "/autodiscover/autodiscover.xml",
    "/ews/exchange.asmx",
    "/owa/auth/logon.aspx",
    "/rpc/",
    "/mapi/",
]

_CVE_CHECKS = [
    ("ProxyLogon", ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"]),
    ("ProxyShell", ["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"]),
    ("ProxyNotShell", ["CVE-2022-41082", "CVE-2022-41040"]),
]


class ExchangeAutodiscoverPlugin(PluginBase):
    id = "web.exchange_autodiscover"
    name = "Microsoft Exchange Exposure"
    description = "Detect exposed Microsoft Exchange and cross-reference with known CVEs"
    category = PluginCategory.web
    severity = Severity.high
    ports = _EXCHANGE_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in _EXCHANGE_PORTS or port.state != "open":
                continue
            scheme = web_scheme(port)
            base_url = f"{scheme}://{host.ip}:{port.number}"
            result = await self._probe(context, base_url, port.number)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, context, base_url: str, port: int) -> FindingData | None:
        detected_endpoints: list[str] = []
        version: str | None = None
        auth_type: str | None = None

        async with httpx.AsyncClient(
            verify=False, timeout=8.0, follow_redirects=True,
                **context.proxy_config()
            ) as client:
            for ep in _EXCHANGE_ENDPOINTS:
                try:
                    resp = await client.get(f"{base_url}{ep}")

                    # Check for NTLM auth challenge (Exchange uses NTLM)
                    www_auth = resp.headers.get("www-authenticate", "")
                    if "ntlm" in www_auth.lower() or "negotiate" in www_auth.lower():
                        detected_endpoints.append(ep)
                        auth_type = "NTLM/Negotiate"
                    elif resp.status_code in (200, 302) and (
                        "microsoft exchange" in resp.text.lower()
                        or "exchangewebservices" in resp.text.lower()
                        or "autodiscover" in resp.text.lower()
                    ):
                        detected_endpoints.append(ep)

                    # Extract OWA version header
                    owa_version = resp.headers.get("x-owa-version", "")
                    if owa_version and not version:
                        version = owa_version

                except Exception:
                    pass

        if not detected_endpoints:
            return None

        # Report CVE families as candidates to verify — we cannot confirm without
        # comparing the exact CU version against Microsoft's fix tables.
        all_cves = [cve for _, cves in _CVE_CHECKS for cve in cves]
        applicable_cves = all_cves
        note = ""
        if version:
            note = (
                f"Detected OWA version: {version}. "
                "Verify whether this version has received all required CUs and SUs. "
            )
        else:
            note = "Version could not be determined — assume unpatched until confirmed otherwise. "

        evidence = f"Detected Exchange endpoints: {', '.join(detected_endpoints)}"
        if version:
            evidence += f"\nOWA Version: {version}"
        if auth_type:
            evidence += f"\nAuthentication: {auth_type}"

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="Microsoft Exchange Exposed",
            description=(
                f"Microsoft Exchange services are accessible at {base_url}. "
                f"{note}"
                "Exchange has been the target of multiple critical CVEs including ProxyLogon, "
                "ProxyShell, and ProxyNotShell. Verify patching status immediately."
            ),
            evidence=evidence,
            remediation=(
                "Apply all available Exchange Cumulative Updates and Security Updates. "
                "Enable Extended Protection for Authentication. "
                "Restrict Exchange management interfaces to internal networks. "
                "Monitor IIS logs for exploitation indicators (CVE-2021-26855 pattern)."
            ),
            references=[
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855",
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473",
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082",
            ],
            cve_ids=applicable_cves[:5] if applicable_cves else ["CVE-2021-26855"],
            port_number=port,
            protocol="tcp",
        )
