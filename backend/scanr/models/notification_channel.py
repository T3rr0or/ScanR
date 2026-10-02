from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class NotificationChannel(Base, TimestampMixin):
    """A person-readable destination for scan summaries: email, Teams or Slack.

    Unlike webhooks (machine-readable JSON for integrations) these carry a
    formatted message. See scanr.core.notifications.
    """

    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # email | slack | teams
    # Email address, or the vault-encrypted incoming-webhook URL for Slack and
    # Teams: those URLs are bearer credentials for posting into a channel.
    target: Mapped[str] = mapped_column(Text, nullable=False)
    events: Mapped[str] = mapped_column(Text, nullable=False)  # JSON list[str]
    # Only notify about a completed scan when a finding reaches this fix-first
    # priority. None = always.
    min_priority: Mapped[float | None] = mapped_column(Float, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_status: Mapped[str | None] = mapped_column(String(20), nullable=True)  # sent | failed
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
