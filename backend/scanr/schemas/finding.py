from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class FindingRead(BaseModel):
    id: str
    scan_id: str
    host_id: str | None
    host_ip: str | None = None
    plugin_id: str
    severity: str
    title: str
    description: str | None
    evidence: str | None
    remediation: str | None
    references: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cve_ids: str | None
    port_number: int | None
    protocol: str | None
    false_positive: bool
    analyst_notes: str | None
    triaged_at: datetime | None = None
    triaged_by: str | None = None
    compliance_tags: str | None = None
    mitre_tags: str | None = None
    remediation_status: str = "open"
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    false_positive: bool | None = None
    analyst_notes: str | None = None
    remediation_status: str | None = None


class FindingBulkUpdate(BaseModel):
    ids: list[str]
    false_positive: bool | None = None
    remediation_status: str | None = None
    analyst_notes: str | None = None
