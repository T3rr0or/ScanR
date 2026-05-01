from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class PluginRun(Base, TimestampMixin):
    __tablename__ = "plugin_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    host_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("hosts.id"), nullable=True, index=True)
    plugin_id: Mapped[str] = mapped_column(String(100), ForeignKey("plugins.id"), nullable=False, index=True)
    host_ip: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
