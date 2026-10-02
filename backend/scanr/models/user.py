from __future__ import annotations

from datetime import datetime
from enum import Enum

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String, Text, false
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid

_MAX_FAILED_ATTEMPTS = 10
_LOCKOUT_MINUTES = 15


class UserRole(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    # Rotated atomically with hashed_password. Refresh tokens must carry this
    # exact generation, preventing an old-password login from crossing a
    # password-change boundary through a separate Redis update.
    password_generation: Mapped[str | None] = mapped_column(String(36), nullable=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(20), default=UserRole.analyst, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Two-factor authentication. The secret is vault-encrypted; it is written
    # during setup and only enforced at login once totp_enabled is set, after
    # the user has proved their authenticator produces matching codes.
    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), nullable=False)
    # Highest time step already accepted, so a code cannot be replayed.
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # JSON list of SHA-256 hashes of the unused recovery codes.
    totp_recovery_codes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Stable identity-provider subject ("iss|sub") once the account has signed
    # in with SSO. Later SSO logins match on this, not on the mutable email.
    oidc_subject: Mapped[str | None] = mapped_column(String(255), unique=True, index=True, nullable=True)

    @property
    def mfa_enabled(self) -> bool:
        return bool(self.totp_enabled)
