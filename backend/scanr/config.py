from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    app_name: str = "ScanR"
    app_version: str = "0.1.0"
    debug: bool = False
    base_dir: Path = Path(__file__).parent.parent

    # Security
    secret_key: str = secrets.token_urlsafe(32)
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # Database
    database_url: str = "sqlite+aiosqlite:///./scanr.db"
    # For PostgreSQL: postgresql+asyncpg://user:pass@localhost/scanr

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    # Credential vault encryption key (Fernet) — 32-byte URL-safe base64
    vault_key: str = ""  # generated on first run if empty

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
    admin_password: str = "changeme"


@lru_cache
def get_settings() -> Settings:
    return Settings()
