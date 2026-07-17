from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class CveMatcherPlugin(PluginBase):
    id = "cve.cve_matcher"
    name = "CVE Version Matcher"
    description = "Match detected service versions against NVD CVE database"
    category = PluginCategory.cve
    severity = Severity.info
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        # TTL-cached KEV id set, fetched once per host instead of per port.
        from scanr.plugins.cve.kev_cache import aget_kev_cve_ids
        kev_ids = await aget_kev_cve_ids()

        for port in host.ports:
            if port.state != "open" or not port.service:
                continue
            svc = port.service
            if not svc.product or not svc.version:
                continue

            matches = await self._match_cves(svc.product, svc.version)
            for cve in matches[:5]:  # cap at 5 CVEs per service
                cve_id = cve["cve_id"]
                is_kev = cve_id in kev_ids
                sev = Severity.critical if is_kev else _map_severity(cve.get("severity", "info"))
                kev_note = " ⚠️ CISA KEV — actively exploited in the wild" if is_kev else ""
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=sev,
                    title=f"{cve_id}: {svc.product} {svc.version}{kev_note}",
                    description=cve.get("description", "") + (
                        "\n\nThis CVE is listed in the CISA Known Exploited Vulnerabilities catalog. "
                        "Immediate patching is required." if is_kev else ""
                    ),
                    evidence=f"Detected: {svc.product} {svc.version} on port {port.number}",
                    remediation=f"Update {svc.product} to a patched version. See https://nvd.nist.gov/vuln/detail/{cve_id}",
                    references=[
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        *(["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"] if is_kev else []),
                    ],
                    cvss_score=cve.get("cvss_score"),
                    cvss_vector=cve.get("cvss_vector"),
                    cve_ids=[cve_id],
                    port_number=port.number,
                    protocol=port.protocol,
                ))
        return findings

    async def _match_cves(self, product: str, version: str) -> list[dict]:
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._match_sync, product, version)

    def _match_sync(self, product: str, version: str) -> list[dict]:
        try:
            from scanr.plugins.cve.nvd_loader import search_by_product
            return search_by_product(product, version)
        except Exception as exc:
            logger.debug("CVE match failed for %s %s: %s", product, version, exc)
            return []


def _map_severity(nvd_severity: str) -> Severity:
    return {
        "critical": Severity.critical,
        "high": Severity.high,
        "medium": Severity.medium,
        "low": Severity.low,
    }.get(nvd_severity.lower(), Severity.info)
