"""AI-generated result attached to a scan (summary, report, false-positive test)."""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class AiResult(Base, TimestampMixin):
    __tablename__ = "ai_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # summary, report, false_positives
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    content: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # JSON: {"text": "..."} or {"items": [...], "methodology": "..."}
    token_usage: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON: {"input_tokens": N, "output_tokens": N, ...}
