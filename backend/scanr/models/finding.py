from __future__ import annotations

from enum import Enum

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, new_uuid


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    host_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("hosts.id"), nullable=True, index=True)
    plugin_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list of URLs

    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cve_ids: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list

    port_number: Mapped[int | None] = mapped_column(nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(5), nullable=True)

    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triaged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    compliance_tags: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list[str]
    mitre_tags: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list[str] of ATT&CK technique IDs
    remediation_status: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="findings", foreign_keys="Finding.scan_id")
    host: Mapped["Host | None"] = relationship(back_populates="findings")
