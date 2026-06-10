from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .finding import Finding
    from .host import Host
    from .report import Report
    from .target import Target

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, new_uuid


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    paused = "paused"
    completed = "completed"
    cancelled = "cancelled"
    failed = "failed"


class ScanProfile(str, Enum):
    quick = "quick"        # top 1000 ports, basic plugins
    standard = "standard"  # top 10000 ports, all non-auth plugins
    full = "full"          # all ports, all plugins including brute-force
    custom = "custom"      # user-defined via profile_json


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.pending, nullable=False, index=True)
    profile: Mapped[str] = mapped_column(String(20), default=ScanProfile.standard, nullable=False)
    profile_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON overrides
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Updated periodically while a scan runs; a watchdog marks scans whose
    # heartbeat has gone stale (worker crash) as failed.
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    credential_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("credentials.id"), nullable=True)
    template_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_templates.id"), nullable=True)
    compare_scan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    webhook_sent: Mapped[bool] = mapped_column(default=False)
    agent_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_agents.id"), nullable=True)

    # stats (denormalized for dashboard speed)
    hosts_total: Mapped[int] = mapped_column(default=0)
    hosts_up: Mapped[int] = mapped_column(default=0)
    findings_critical: Mapped[int] = mapped_column(default=0)
    findings_high: Mapped[int] = mapped_column(default=0)
    findings_medium: Mapped[int] = mapped_column(default=0)
    findings_low: Mapped[int] = mapped_column(default=0)
    findings_info: Mapped[int] = mapped_column(default=0)

    targets: Mapped[list["Target"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    hosts: Mapped[list["Host"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan", foreign_keys="Finding.scan_id")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
