from __future__ import annotations

from datetime import datetime

from typing import Literal

from pydantic import BaseModel, Field


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
    impact: str | None = None
    template_id: str | None = None
    references: str | None
    cvss_score: float | None
    cvss_vector: str | None
    vpr_score: float | None = None
    priority_score: float | None = None
    priority_reasons: str | None = None  # JSON list[str]
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    cve_ids: str | None
    first_seen_scan_id: str | None = None
    last_seen_scan_id: str | None = None
    port_number: int | None
    protocol: str | None
    false_positive: bool
    analyst_notes: str | None
    triaged_at: datetime | None = None
    triaged_by: str | None = None
    compliance_tags: str | None = None
    mitre_tags: str | None = None
    remediation_status: str = "open"
    # Latest retest outcome, so the findings list can show verification state
    # without a second request per row. Full history: GET /findings/{id}/retests
    last_retest_at: datetime | None = None
    last_retest_verdict: str | None = None
    # True only when ScanR reproduced the issue mechanically (core/validation.py).
    validated: bool = False
    validated_at: datetime | None = None
    validation_method: str | None = None
    validation_evidence: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    false_positive: bool | None = None
    analyst_notes: str | None = None
    remediation_status: str | None = None
    # Report wording. The title is deliberately not editable: trends, triage
    # carry-forward and SARIF identify an issue by it.
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    description: str | None = Field(None, max_length=50_000)
    impact: str | None = Field(None, max_length=50_000)
    remediation: str | None = Field(None, max_length=50_000)
    evidence: str | None = Field(None, max_length=500_000)
    cvss_score: float | None = Field(None, ge=0, le=10)
    cvss_vector: str | None = Field(None, max_length=255)
    references: list[str] | None = Field(None, max_length=100)


class FindingBulkUpdate(BaseModel):
    ids: list[str]
    false_positive: bool | None = None
    remediation_status: str | None = None
    analyst_notes: str | None = None
