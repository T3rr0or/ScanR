from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scan import Scan

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, new_uuid


class TargetType(str, Enum):
    ip = "ip"
    cidr = "cidr"
    hostname = "hostname"
    range = "range"  # e.g. 10.0.0.1-10.0.0.50


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(20), nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="targets")
