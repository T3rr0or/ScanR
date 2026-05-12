from __future__ import annotations

from enum import Enum

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class CredentialType(str, Enum):
    ssh = "ssh"
    wmi = "wmi"
    snmp = "snmp"
    http_basic = "http_basic"
    http_form = "http_form"
    ftp = "ftp"
    smb = "smb"


class Credential(Base, TimestampMixin):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(30), nullable=False)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_data: Mapped[str] = mapped_column(Text, nullable=False)  # Fernet-encrypted JSON
    hash_type: Mapped[str | None] = mapped_column(String(20), nullable=True)  # ntlm, netntlm, sha1, etc.
    engagement_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
