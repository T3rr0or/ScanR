from __future__ import annotations

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class Plugin(Base, TimestampMixin):
    __tablename__ = "plugins"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)  # e.g. "ssl_tls.heartbleed"
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    default_severity: Mapped[str] = mapped_column(String(20), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    requires_auth: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cve_ids: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
