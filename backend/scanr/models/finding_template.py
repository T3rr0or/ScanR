from __future__ import annotations

from sqlalchemy import Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class FindingTemplate(Base, TimestampMixin):
    """A reusable, reviewed write-up for one kind of finding (the team's
    finding library). Text is copied into a finding when applied, so later
    edits to the library never rewrite findings already reported."""

    __tablename__ = "finding_templates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    title: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list[str]
    cve_ids: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list[str]
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list[str]
    # Scanner findings this entry describes: plugin ids, optionally narrowed by
    # a case-insensitive title substring (one plugin can report several issues).
    plugin_ids: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list[str]
    title_match: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
