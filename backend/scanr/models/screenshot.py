from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, new_uuid

if TYPE_CHECKING:
    from .host import Host
    from .scan import Scan


class Screenshot(Base, TimestampMixin):
    __tablename__ = "screenshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    host_id: Mapped[str] = mapped_column(String(36), ForeignKey("hosts.id"), nullable=False, index=True)
    port_number: Mapped[int] = mapped_column(nullable=False)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int | None] = mapped_column(nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    host: Mapped["Host"] = relationship()
    scan: Mapped["Scan"] = relationship()
