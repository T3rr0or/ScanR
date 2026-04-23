from __future__ import annotations
from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, TimestampMixin, new_uuid


class Wordlist(Base, TimestampMixin):
    __tablename__ = "wordlists"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    # NULL user_id = built-in / global (visible to all users)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    type: Mapped[str] = mapped_column(String(20), nullable=False)
    # type: "usernames" | "passwords" | "credentials" | "paths"
    source: Mapped[str] = mapped_column(String(20), default="custom", nullable=False)
    # source: "builtin" | "custom" | "seclists"
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
