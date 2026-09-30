"""Run Nuclei's network/ and javascript/ templates against non-HTTP ports.

The HTTP runner (``nuclei.runner``) only points Nuclei at web ports, so the
entire ``network/`` and ``javascript/`` template trees — WebLogic T3, Ghostcat,
unauthenticated databases, exposed RPC/telnet services and so on — never ran.
This plugin covers those templates against the non-web ports a scan already
found open.

Detection method and template set are Nuclei's own; this module only decides
which open ports to point them at and how to parse the JSON output. Templates
whose only signal is an out-of-band (OAST/interactsh) callback cannot confirm
through the scanner's egress proxy, so ``-no-interactsh`` is passed and those
templates simply do not match rather than producing an unverifiable finding.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "unknown": Severity.info,
}

# Template directories to run. These are non-HTTP protocol templates, so they
# complement (never overlap) the HTTP runner's http/ directories.
NETWORK_TEMPLATES = ["network", "javascript"]

# Ports that carry HTTP are the HTTP runner's job; skip them here so a service
# is not scanned twice. This also spares the network templates from being
# pointed at web ports where they cannot match.
_MAX_TARGETS = 50

# Prefer ports that frequently host services covered by Nuclei's network
# templates when a scan finds more open ports than the per-host cap permits.
_PRIORITY_PORTS = (
    22, 23, 53, 111, 135, 139, 445, 1433, 1521, 3306, 3389, 5432,
    5900, 5985, 5986, 6379, 7001, 7002, 8089, 9200, 11211, 27017,
)
_PRIORITY_PORT_RANK = {port: rank for rank, port in enumerate(_PRIORITY_PORTS)}


def _target_sort_key(port: object) -> tuple[int, int, int]:
    """Rank known network services first, then fingerprinted, then other ports."""
    number = int(getattr(port, "number", 0) or 0)
    service = getattr(port, "service", None)
    name = str(getattr(service, "name", "") or "").lower()
    product = str(getattr(service, "product", "") or "").strip()
    fingerprinted = bool(name and name not in {"unknown", "tcpwrapped"}) or bool(product)
    return (
        _PRIORITY_PORT_RANK.get(number, len(_PRIORITY_PORT_RANK)),
        0 if fingerprinted else 1,
        number,
    )


class NucleiNetworkRunnerPlugin(PluginBase):
    id = "nuclei.network_runner"
    name = "Nuclei Network Template Scanner"
    description = "Run Nuclei network and javascript templates against non-HTTP services"
    category = PluginCategory.services
    severity = Severity.info
    ports = None  # applies to any open non-web port

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not shutil.which("nuclei"):
            logger.warning("nuclei binary not found — skipping nuclei.network_runner plugin")
            return []

        ports = [
            port
            for port in host.ports
            if port.state == "open" and not is_web_port(port)
        ]
        if not ports:
            return []
        # Bound the work while preferring common Nuclei services and ports with
        # service fingerprints. Port discovery is usually numeric, so slicing
        # the original list would silently starve high-numbered services.
        ports.sort(key=_target_sort_key)
        if len(ports) > _MAX_TARGETS:
            skipped = len(ports) - _MAX_TARGETS
            await context.log.info(
                f"Nuclei network scan capped at {_MAX_TARGETS} of {len(ports)} open non-web ports; "
                f"{skipped} lower-priority ports were skipped",
                phase="plugin",
            )
            logger.warning(
                "nuclei network scan capped at %d of %d ports for %s (%d skipped)",
                _MAX_TARGETS, len(ports), host.ip, skipped,
            )
        targets = [f"{host.ip}:{port.number}" for port in ports[:_MAX_TARGETS]]

        return await self._run_nuclei(targets, context)

    async def _run_nuclei(self, targets: list[str], context: "ScanContext") -> list[FindingData]:
        rate = 50
        try:
            rate = int(context.performance_config().get("nuclei_rate") or 50)
        except Exception:
            pass

        cmd = [
            "nuclei",
            "-t", ",".join(NETWORK_TEMPLATES),
            "-json",
            "-silent",
            "-no-interactsh",
            "-timeout", "5",
            "-retries", "1",
            "-rate-limit", str(rate),
        ]
        for target in targets:
            cmd.extend(["-u", target])

        await context.log.info(f"$ nuclei -t {','.join(NETWORK_TEMPLATES)} ({len(targets)} targets)", phase="plugin")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180.0)
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            logger.warning("nuclei network scan timed out for %d targets", len(targets))
            return []
        except Exception as exc:
            logger.warning("nuclei network scan error: %s", exc)
            return []

        findings: list[FindingData] = []
        for line in stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding = self._parse_result(result)
            if finding:
                findings.append(finding)

        logger.info("nuclei network scan found %d issues across %d targets", len(findings), len(targets))
        return findings

    def _parse_result(self, result: dict) -> FindingData | None:
        try:
            info = result.get("info", {})
            name = info.get("name", "Unknown")
            severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.info)
            description = info.get("description", "")
            remediation = info.get("remediation", "")

            template_id = result.get("template-id", "")

            # A CVE id can appear in the tags, the classification block, or the
            # template id itself (templates are usually named CVE-YYYY-NNNN).
            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]
            cve_ids = {t.upper() for t in tags if str(t).upper().startswith("CVE-")}
            classification = info.get("classification") or {}
            classified = classification.get("cve-id")
            if isinstance(classified, str):
                classified = [classified]
            for cid in classified or []:
                if str(cid).upper().startswith("CVE-"):
                    cve_ids.add(str(cid).upper())
            if str(template_id).upper().startswith("CVE-"):
                cve_ids.add(str(template_id).upper())
            cve_ids = sorted(cve_ids)

            reference = info.get("reference", [])
            if isinstance(reference, str):
                reference = [reference]

            matcher_name = result.get("matcher-name", "")
            matched_at = result.get("matched-at", "")

            # matched-at is "ip:port"; recover the port for the finding.
            port_number = None
            if isinstance(matched_at, str) and ":" in matched_at:
                tail = matched_at.rsplit(":", 1)[-1].split("/", 1)[0]
                if tail.isdigit():
                    port_number = int(tail)

            return FindingData(
                plugin_id=self.id,
                severity=severity,
                title=f"[Nuclei] {name}" + (f" — {matcher_name}" if matcher_name else ""),
                description=description or f"Nuclei template '{template_id}' matched.",
                evidence=f"Matched at: {matched_at}" + (f"\nTemplate: {template_id}" if template_id else ""),
                remediation=remediation,
                references=list(reference)[:5],
                cve_ids=cve_ids,
                port_number=port_number,
                protocol="tcp",
            )
        except Exception as exc:
            logger.debug("Failed to parse nuclei network result: %s", exc)
            return None
