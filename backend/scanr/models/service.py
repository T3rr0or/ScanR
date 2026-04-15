from __future__ import annotations

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, new_uuid


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    port_id: Mapped[str] = mapped_column(String(36), ForeignKey("ports.id"), nullable=False, unique=True)
    name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)
    tunnel: Mapped[str | None] = mapped_column(String(20), nullable=True)  # ssl, ssh, etc.

    port: Mapped["Port"] = relationship(back_populates="service")
