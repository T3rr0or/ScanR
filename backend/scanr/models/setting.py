from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class AppSetting(Base, TimestampMixin):
    """Encrypted, admin-managed key/value settings entered at runtime.

    Used for secrets that the operator sets from the web app rather than the
    environment — currently AI provider API keys. ``value`` holds Fernet
    ciphertext (via scanr.credentials.vault); it is never returned by the API.
    """

    __tablename__ = "app_settings"

    # The setting name is the primary key, e.g. "ai.api_key.anthropic".
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)  # Fernet ciphertext
