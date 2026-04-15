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
                cvss_vector=data.cvss_vector,
                cve_ids=json.dumps(data.cve_ids) if data.cve_ids else None,
                port_number=data.port_number,
                protocol=data.protocol,
                compliance_tags=json.dumps(compliance_tags) if compliance_tags else None,
                mitre_tags=json.dumps(mitre_tags) if mitre_tags else None,
                first_seen_scan_id=self.scan_id,
                last_seen_scan_id=self.scan_id,
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

            # Fire webhook for critical findings
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
