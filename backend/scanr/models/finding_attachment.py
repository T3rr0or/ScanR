from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class FindingAttachment(Base, TimestampMixin):
    """Evidence file on a finding: a screenshot, saved request, log or PDF.

    The bytes live on disk under EVIDENCE_DIR/<finding_id>/<id>; the name is
    never derived from user input. Rows go when their finding does
    (ON DELETE CASCADE) and the API's cleanup removes the orphaned files.
    """

    __tablename__ = "finding_attachments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)  # display only
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)  # as detected, not as claimed
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    caption: Mapped[str | None] = mapped_column(Text, nullable=True)
    uploaded_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
