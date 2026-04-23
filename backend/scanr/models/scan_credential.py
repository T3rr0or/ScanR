from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class ScanCredential(Base, TimestampMixin):
    """Per-scan credential — scoped to one scan, not shared globally."""

    __tablename__ = "scan_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(40), nullable=False)
    # role values: "primary_domain" | "local_admin" | "ssh" | "snmp" | "api" | "generic"
    type: Mapped[str] = mapped_column(String(30), nullable=False)
    # type values: same as CredentialType: "smb" | "ssh" | "snmp" | "http_basic" | "wmi"
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_data: Mapped[str] = mapped_column(Text, nullable=False)  # Fernet-encrypted JSON with password etc.
    # If user checks "Save to vault", we also create a Credential record:
    vault_credential_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("credentials.id"), nullable=True
    )
