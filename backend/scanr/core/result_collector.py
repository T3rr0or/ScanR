from __future__ import annotations

import asyncio
import json
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from scanr.core.compliance import tags_for_plugin
from scanr.core.mitre import mitre_tags_for_plugin
from scanr.core.plugin_base import FindingData
from scanr.models import Finding, Scan
from scanr.models.base import new_uuid

logger = logging.getLogger(__name__)

# Severity → stat column map
_SEVERITY_COLS = {
    "critical": "findings_critical",
    "high": "findings_high",
    "medium": "findings_medium",
    "low": "findings_low",
    "info": "findings_info",
}


def _compute_vpr(cvss_score: float | None, cve_ids: list[str] | None) -> float | None:
    """Vulnerability Priority Rating: CVSS × KEV multiplier, capped at 10."""
    if cvss_score is None:
        return None
    try:
        from scanr.plugins.cve.nvd_loader import get_kev_cve_ids
        kev = get_kev_cve_ids()
        is_kev = bool(cve_ids and any(c in kev for c in cve_ids))
    except Exception:
        is_kev = False
    return round(min(cvss_score * (2.0 if is_kev else 1.0), 10.0), 2)


class ResultCollector:
    """Thread-safe accumulator that flushes findings to the DB and updates scan stats."""

    def __init__(self, scan_id: str, db: AsyncSession, scan_log=None, user_id: str | None = None):
        self.scan_id = scan_id
        self.db = db
        self._scan_log = scan_log
        self._user_id = user_id
        self._lock = asyncio.Lock()
        self._cached_scan: "Scan | None" = None

    async def add_finding(self, host_id: str | None, data: FindingData) -> None:
        async with self._lock:
            compliance_tags = tags_for_plugin(data.plugin_id)
            mitre_tags = mitre_tags_for_plugin(data.plugin_id)

            # Triage carryforward: look up a prior finding with same plugin/host/port
            # across any previous scan for this user, and carry forward triage state.
            prior = await self._find_prior_triage(host_id, data)

            cve_ids_list = data.cve_ids if data.cve_ids else None
            finding = Finding(
                id=new_uuid(),
                scan_id=self.scan_id,
                host_id=host_id,
                plugin_id=data.plugin_id,
                severity=data.severity.value,
                title=data.title,
                description=data.description,
                evidence=data.evidence,
                remediation=data.remediation,
                references=json.dumps(data.references) if data.references else None,
                cvss_score=data.cvss_score,
                cvss_vector=data.cvss_vector,
                vpr_score=_compute_vpr(data.cvss_score, cve_ids_list),
                cve_ids=json.dumps(cve_ids_list) if cve_ids_list else None,
                port_number=data.port_number,
                protocol=data.protocol,
                compliance_tags=json.dumps(compliance_tags) if compliance_tags else None,
                mitre_tags=json.dumps(mitre_tags) if mitre_tags else None,
                first_seen_scan_id=self.scan_id,
                last_seen_scan_id=self.scan_id,
                # Carry forward triage state from prior scan if available
                false_positive=prior.false_positive if prior else False,
                remediation_status=prior.remediation_status if prior else "open",
                analyst_notes=prior.analyst_notes if prior else None,
                triaged_by=prior.triaged_by if prior else None,
            )
            self.db.add(finding)

            # Update scan stats (cached to avoid N+1 queries)
            from sqlalchemy import select
            if self._cached_scan is None:
                result = await self.db.execute(select(Scan).where(Scan.id == self.scan_id))
                self._cached_scan = result.scalar_one_or_none()
            scan = self._cached_scan
            if scan:
                col = _SEVERITY_COLS.get(data.severity.value, "findings_info")
                setattr(scan, col, getattr(scan, col) + 1)

            await self.db.flush()
            logger.debug("Finding recorded: %s [%s] on host %s", data.title, data.severity, host_id)

            # Fire webhook for critical findings (was dead code — fixed)
            if data.severity.value == "critical" and self._user_id:
                try:
                    from scanr.core.webhook_dispatcher import dispatch
                    await dispatch("finding.critical", {
                        "scan_id": self.scan_id,
                        "finding_id": finding.id,
                        "title": data.title,
                        "plugin_id": data.plugin_id,
                        "severity": data.severity.value,
                    }, self._user_id, self.db)
                except Exception as exc:
                    logger.debug("Webhook dispatch error: %s", exc)

    async def _find_prior_triage(self, host_id: str | None, data: "FindingData") -> "Finding | None":
        """Look up the most recent triaged finding with the same canonical key."""
        if not host_id:
            return None
        try:
            from sqlalchemy import select
            from scanr.models import Host
            result = await self.db.execute(
                select(Finding)
                .join(Host, Finding.host_id == Host.id)
                .where(
                    Finding.plugin_id == data.plugin_id,
                    Finding.port_number == data.port_number,
                    Finding.scan_id != self.scan_id,
                    (Finding.false_positive == True)
                    | (Finding.remediation_status != "open")
                    | (Finding.analyst_notes.isnot(None)),
                )
                .order_by(Finding.created_at.desc())
                .limit(1)
            )
            return result.scalar_one_or_none()
        except Exception:
            return None
