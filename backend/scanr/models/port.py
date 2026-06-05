from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .host import Host
    from .service import Service

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, new_uuid


class PortProtocol(str, Enum):
    tcp = "tcp"
    udp = "udp"


class PortState(str, Enum):
    open = "open"
    closed = "closed"
    filtered = "filtered"
    open_filtered = "open|filtered"


class Port(Base, TimestampMixin):
    __tablename__ = "ports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    host_id: Mapped[str] = mapped_column(String(36), ForeignKey("hosts.id"), nullable=False, index=True)
    number: Mapped[int] = mapped_column(nullable=False)
    protocol: Mapped[str] = mapped_column(String(5), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(50), nullable=True)
    banner: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    host: Mapped["Host"] = relationship(back_populates="ports")
    service: Mapped["Service | None"] = relationship(back_populates="port", uselist=False, cascade="all, delete-orphan")
