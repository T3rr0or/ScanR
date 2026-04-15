from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ReportCreate(BaseModel):
    scan_id: str
    format: str  # html | pdf | json | csv


class ReportRead(BaseModel):
    id: str
    scan_id: str
    format: str
    status: str
    file_path: str | None
    error_message: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
