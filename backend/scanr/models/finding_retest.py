from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from .finding import Finding

from .base import Base, TimestampMixin, new_uuid


class RetestStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class RetestVerdict(str, Enum):
    """What the re-run concluded about the original finding."""
    resolved = "resolved"          # the plugin no longer reports it
    still_present = "still_present"
    inconclusive = "inconclusive"  # ran, but could not decide (e.g. host now down)


class FindingRetest(Base, TimestampMixin):
    """One re-run of the plugin that produced a finding, against the same target.

    Kept as history rather than a single mutable column on Finding: "verified
    fixed on 3 March, still present on 12 February" is exactly the evidence trail
    a retest report needs, and overwriting it would destroy that.
    """

    __tablename__ = "finding_retests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=False, index=True
    )
    requested_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )

    status: Mapped[str] = mapped_column(String(20), default=RetestStatus.pending, nullable=False)
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    #: What the re-run observed, for a human to check the verdict against.
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="retests")
