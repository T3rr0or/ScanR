from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    app_name: str = "ScanR"
    app_version: str = "0.20.1"
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

    # Scan scope safety — hostnames/IPs that may never be a scan target because
    # they belong to the scanner's own infrastructure. Comma-separated; merged
    # with the built-in loopback/link-local/metadata denylist. Loopback,
    # link-local (incl. 169.254.169.254 cloud metadata), multicast, reserved,
    # and unspecified addresses are always rejected regardless of this list.
    scan_target_denylist: str = "localhost,postgres,redis,db,scanr-api,scanr-worker"

    # Trusted reverse-proxy peers. The X-Forwarded-For header is only honoured
    # for rate limiting when the direct TCP peer is in this comma-separated list
    # of IPs/CIDRs. Otherwise the header is ignored so clients cannot spoof
    # their source IP to bypass rate limits. Empty = never trust XFF.
    trusted_proxies: str = ""

    # Mark scans whose worker heartbeat has gone stale (worker crash/OOM) as
    # failed after this many seconds. Prevents scans stuck in "running" forever.
    scan_heartbeat_timeout: int = 300  # seconds

    # Proxy — route HTTP scan traffic through Burp/SOCKS5 pivot
    proxy_url: str = ""  # e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080
    proxy_type: str = ""  # auto-detected from URL scheme if empty; force "http" or "socks5"

    # Webhook events
    webhook_scan_completed: bool = True  # fire webhook when scan finishes

    # ── AI providers ─────────────────────────────────────────────────────────
    # Default provider/model for AI features. Provider ∈ anthropic|openai|deepseek.
    # ai_model blank = use the provider's built-in default. Keys are read from the
    # environment and never logged or sent to the model as content.
    ai_provider: str = "anthropic"
    ai_model: str = ""
    ai_max_tokens: int = 2048
    # Per-minute input token cap for agent loop. 0 = no limit.
    # Anthropic free tier = 10,000/min. Set to 0 for pay-as-you-go plans.
    ai_rate_limit_tokens_per_min: int = 0
    # Seconds before a running agent run with a stale heartbeat is auto-failed
    # (worker died mid-run). Generous: LLM calls + rate/command sleeps take time.
    ai_agent_heartbeat_timeout: int = 900
    openai_api_key: str = ""
    deepseek_api_key: str = ""
    anthropic_api_key: str = ""

    # ── AI command-execution sandbox (see docs/ai-sandbox-design.md) ──────────
    # Empty SANDBOX_RUNNER_URL = command execution disabled (fail-closed). The
    # runner is a dedicated, socket-isolated service; the worker talks to it over
    # the internal network and never touches Docker itself.
    sandbox_runner_url: str = ""
    sandbox_token: str = ""
    sandbox_image: str = "scanr-sandbox:latest"
    sandbox_cmd_timeout: int = 120  # per-command wall-clock seconds

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

    @property
    def scan_denylist(self) -> set[str]:
        return {h.strip().lower() for h in self.scan_target_denylist.split(",") if h.strip()}

    @property
    def trusted_proxy_list(self) -> list[str]:
        return [p.strip() for p in self.trusted_proxies.split(",") if p.strip()]

    @field_validator("algorithm")
    @classmethod
    def _check_algorithm(cls, v: str) -> str:
        # Constrain JWT algorithm to an HMAC allowlist — an env misconfig to
        # 'none' (or an asymmetric alg with a confused key) must fail fast at
        # startup rather than silently weaken token verification.
        allowed = {"HS256", "HS384", "HS512"}
        if v not in allowed:
            raise ValueError(f"ALGORITHM must be one of {sorted(allowed)} (got {v!r})")
        return v

    @model_validator(mode="after")
    def _check_required_secrets(self) -> "Settings":
        if not self.secret_key:
            raise ValueError(
                'SECRET_KEY must be set in the environment (generate with: python3 -c "import secrets; print(secrets.token_urlsafe(32))")'
            )
        if len(self.secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        if self.vault_key:
            try:
                from cryptography.fernet import Fernet

                Fernet(self.vault_key.encode())
            except Exception:
                raise ValueError(
                    "VAULT_KEY is not a valid Fernet key. "
                    'Generate one with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # populated from environment by pydantic-settings
