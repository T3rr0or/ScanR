from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

# Map nuclei severity strings to ScanR Severity
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "unknown": Severity.info,
}

# Nuclei template categories to use
NUCLEI_TEMPLATES = [
    "cves",
    "exposures",
    "misconfigs",
    "default-logins",
    "vulnerabilities",
]


class NucleiRunnerPlugin(PluginBase):
    id = "nuclei.runner"
    name = "Nuclei Template Scanner"
    description = "Run Nuclei vulnerability scanner templates against HTTP/HTTPS services"
    category = PluginCategory.web
    severity = Severity.info
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not shutil.which("nuclei"):
            logger.warning("nuclei binary not found — skipping nuclei.runner plugin")
            return []

        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            scheme = web_scheme(port)
            url = f"{scheme}://{host.ip}:{port.number}"
            port_findings = await self._run_nuclei(url, port.number, context)
            findings.extend(port_findings)
        return findings

    async def _run_nuclei(self, url: str, port: int, context: "ScanContext") -> list[FindingData]:
        cmd = [
            "nuclei",
            "-u", url,
            "-t", ",".join(NUCLEI_TEMPLATES),
            "-json",
            "-silent",
            "-timeout", "5",
            "-retries", "1",
            "-rate-limit", "50",
        ]

        await context.log.info(f"$ {' '.join(cmd)}", phase="plugin")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120.0)
        except asyncio.TimeoutError:
            logger.warning("nuclei timed out for %s", url)
            return []
        except Exception as exc:
            logger.warning("nuclei error for %s: %s", url, exc)
            return []

        findings = []
        for line in stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
                finding = self._parse_result(result, port)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                continue

        logger.info("nuclei found %d issues for %s", len(findings), url)
        return findings

    def _parse_result(self, result: dict, port: int) -> FindingData | None:
        try:
            info = result.get("info", {})
            name = info.get("name", "Unknown")
            sev_str = info.get("severity", "info").lower()
            severity = _SEVERITY_MAP.get(sev_str, Severity.info)
            description = info.get("description", "")
            remediation = info.get("remediation", "")
            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]

            reference = info.get("reference", [])
            if isinstance(reference, str):
                reference = [reference]

            cve_ids = [t for t in tags if t.startswith("CVE-")]
            matcher_name = result.get("matcher-name", "")
            matched_at = result.get("matched-at", "")
            template_id = result.get("template-id", "")

            return FindingData(
                plugin_id=self.id,
                severity=severity,
                title=f"[Nuclei] {name}" + (f" — {matcher_name}" if matcher_name else ""),
                description=description or f"Nuclei template '{template_id}' matched.",
                evidence=f"Matched at: {matched_at}" + (f"\nTemplate: {template_id}" if template_id else ""),
                remediation=remediation,
                references=reference[:5],
                cve_ids=cve_ids,
                port_number=port,
                protocol="tcp",
            )
        except Exception as exc:
            logger.debug("Failed to parse nuclei result: %s", exc)
            return None
