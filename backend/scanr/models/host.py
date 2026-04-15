from __future__ import annotations

from enum import Enum

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, new_uuid


class HostStatus(str, Enum):
    up = "up"
    down = "down"
    unknown = "unknown"


class Host(Base, TimestampMixin):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)  # IPv4/IPv6
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_accuracy: Mapped[int | None] = mapped_column(nullable=True)
    os_family: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default=HostStatus.unknown, nullable=False)
    raw_nmap_xml: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="hosts")
    ports: Mapped[list["Port"]] = relationship(back_populates="host", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="host")
