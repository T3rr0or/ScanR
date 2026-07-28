from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class Webhook(Base, TimestampMixin):
    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    # HMAC signing secret, stored as Fernet ciphertext when VAULT_KEY is set (see
    # scanr.core.webhook_dispatcher.decrypt_secret). Text, not String(255):
    # ciphertext is substantially longer than the plaintext it wraps.
    secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    events: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list[str]
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
