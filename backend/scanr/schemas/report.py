from __future__ import annotations

from datetime import datetime

from typing import Literal

from pydantic import BaseModel, Field

# Must stay in sync with the dispatch in scanr.reporting.report_engine. Validated
# as a Literal rather than a bare str: an unknown format used to be accepted, a
# job queued, and the failure surfaced only in the worker as a report stuck at
# "failed" — a 422 at the boundary says what is wrong, immediately.
ReportFormat = Literal["html", "pdf", "json", "csv", "sarif", "bloodhound", "docx"]


class ReportCreate(BaseModel):
    scan_id: str
    format: ReportFormat
    # Word reports only. template_id None = the built-in template.
    template_id: str | None = None
    title: str | None = Field(None, max_length=255)
    client: str | None = Field(None, max_length=255)
    author: str | None = Field(None, max_length=255)
    classification: str | None = Field(None, max_length=100)
    include_info: bool = False


class ReportRead(BaseModel):
    id: str
    scan_id: str
    format: str
    status: str
    file_path: str | None
    error_message: str | None
    template_id: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
