from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ScanCreate(BaseModel):
    name: str
    description: str | None = None
    targets: list[str]          # raw target strings
    profile: str = "standard"   # quick | standard | full | custom
    profile_json: str | None = None
    credential_id: str | None = None


class ScanSummary(BaseModel):
    id: str
    name: str
    status: str
    profile: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    hosts_total: int
    hosts_up: int
    findings_critical: int
    findings_high: int
    findings_medium: int
    findings_low: int
    findings_info: int

    model_config = {"from_attributes": True}


class ScanRead(ScanSummary):
    description: str | None
    error_message: str | None
    user_id: str

    model_config = {"from_attributes": True}
