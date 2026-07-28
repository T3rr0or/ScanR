from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from .finding import Finding

from .base import Base, TimestampMixin, new_uuid


class TicketLink(Base, TimestampMixin):
    """A finding's ticket in an external system.

    ``provider`` is generic rather than a TOPdesk-specific table so adding Jira or
    ServiceNow later is a new value, not a new migration.

    The unique constraint on (finding_id, provider) is the durable half of
    idempotency: even if two operators press "create ticket" at the same instant,
    the database refuses the second row. The provider-side dedup (searching by
    external number before creating) handles the case where the link was lost but
    the ticket exists.
    """

    __tablename__ = "ticket_links"
    __table_args__ = (
        UniqueConstraint("finding_id", "provider", name="uq_ticket_links_finding_provider"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)

    #: Provider's internal id (TOPdesk incident UUID).
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    #: Human-facing reference shown to operators (TOPdesk incident number, "I 2403 001").
    external_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Last status read back from the provider, if it was ever refreshed.
    external_status: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="ticket_links")
