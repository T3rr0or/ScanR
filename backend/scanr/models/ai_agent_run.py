"""A guided/autonomous AI agent run against a scan (status, transcript, usage)."""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class AiAgentRun(Base, TimestampMixin):
    __tablename__ = "ai_agent_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    # queued | running | completed | failed | cancelled
    mode: Mapped[str] = mapped_column(String(20), nullable=False)  # guided | autonomous
    # Max reasoning iterations before the run stops (None = engine default).
    max_iterations: Mapped[int | None] = mapped_column(nullable=True)
    # Token safety cap before the run stops (None = engine default ~200k).
    max_tokens: Mapped[int | None] = mapped_column(nullable=True)
    # Per-minute input token rate cap (None = engine/global default, 0 = unlimited).
    rate_limit_tokens_per_min: Mapped[int | None] = mapped_column(nullable=True)
    # JSON: {aggressive, allow_privilege_escalation, allow_exploitation}. Null = none.
    capabilities: Mapped[str | None] = mapped_column(Text, nullable=True)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stop_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    final_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    actions: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list of actions
    token_usage: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # When set (JSON {approval_id, tool, args, reason}), the run is paused in
    # guided mode awaiting an operator allow/deny decision.
    pending_approval: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Full chat conversation (JSON array of serialized messages) — enables
    # resuming the agent loop with follow-up user messages.
    conversation: Mapped[str | None] = mapped_column(Text, nullable=True)
