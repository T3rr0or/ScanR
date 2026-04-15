from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ScheduleCreate(BaseModel):
    name: str
    description: str | None = None
    targets: list[str]           # list of IPs / CIDRs / domains
    scan_profile_json: str = "{}"  # JSON-encoded scan config overrides
    cron_expr: str               # e.g. "0 2 * * 1" (every Monday 02:00)
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    targets: list[str] | None = None
    scan_profile_json: str | None = None
    cron_expr: str | None = None
    enabled: bool | None = None


class ScheduleRead(BaseModel):
    id: str
    name: str
    description: str | None
    targets: list[str]
    cron_expr: str
    enabled: bool
    next_run: datetime | None
    last_run: datetime | None
    last_scan_id: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
