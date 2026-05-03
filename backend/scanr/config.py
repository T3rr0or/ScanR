from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    app_name: str = "ScanR"
    app_version: str = "0.9.0"
    debug: bool = False
    base_dir: Path = Path(__file__).parent.parent

    # Security
    secret_key: str  # Required — no default; must be set in environment
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # CORS — comma-separated origins allowed to call the API
    allowed_origins: str = "http://localhost"
    secure_cookies: bool = True

    # Database
    database_url: str = "sqlite+aiosqlite:///./scanr.db"
    # For PostgreSQL: postgresql+asyncpg://user:pass@localhost/scanr

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # Credential vault encryption key (Fernet) — 32-byte URL-safe base64
    vault_key: str = ""

    # Scan defaults
    max_concurrent_hosts: int = 50
    max_concurrent_plugins: int = 20
    default_scan_timeout: int = 3600  # seconds

    # Reports output directory
    reports_dir: Path = Path("./reports")

    # NVD CVE feed cache
    nvd_cache_dir: Path = Path("./nvd_cache")

    # Admin bootstrap (first-run seed)
    admin_email: str = "admin@scanr.local"
    admin_password: str  # Required — no default; must be set in environment

    # Self-update is intentionally opt-in. Enabling it means the API process can
    # run the configured update command on behalf of an admin user.
    self_update_enabled: bool = False
    self_update_command: str = "docker-compose pull && docker-compose up -d"
    self_update_workdir: Path = Path("/opt/scanr")

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @model_validator(mode="after")
    def _check_required_secrets(self) -> "Settings":
        if not self.secret_key:
            raise ValueError("SECRET_KEY must be set in the environment (generate with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\")")
        if len(self.secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        if self.vault_key:
            try:
                from cryptography.fernet import Fernet
                Fernet(self.vault_key.encode())
            except Exception:
                raise ValueError(
                    "VAULT_KEY is not a valid Fernet key. "
                    "Generate one with: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
