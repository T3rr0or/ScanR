from __future__ import annotations

from enum import Enum

from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .finding_retest import FindingRetest
    from .host import Host
    from .scan import Scan
    from .ticket_link import TicketLink

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
    vpr_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_ids: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list

    port_number: Mapped[int | None] = mapped_column(nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(5), nullable=True)

    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Proof of exploitation, not an opinion. Set only when ScanR mechanically
    # reproduced the issue (today: a payload that executed in a real browser —
    # see core/validation.py); never by a model or an analyst asserting it, which
    # is what keeps the flag worth filtering on.
    validated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    validation_method: Mapped[str | None] = mapped_column(String(40), nullable=True)
    validation_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Latest retest outcome, denormalised from finding_retests so the findings
    # list can show verification state without a per-row subquery. The history
    # table remains the source of truth.
    last_retest_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_retest_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
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
    retests: Mapped[list["FindingRetest"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan",
    )
    ticket_links: Mapped[list["TicketLink"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan",
    )
