from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scan import Scan

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, new_uuid


class ReportFormat(str, Enum):
    html = "html"
    pdf = "pdf"
    json = "json"
    csv = "csv"
    sarif = "sarif"
    bloodhound = "bloodhound"


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    error_message: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="reports")
