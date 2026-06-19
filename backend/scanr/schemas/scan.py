from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class ScanCredentialIn(BaseModel):
    """Inline credential provided at scan creation time."""

    role: str = Field(default="primary_domain", max_length=50)  # "primary_domain" | "local_admin" | "ssh" | ...
    type: str = Field(default="smb", max_length=30)             # credential type
    username: str | None = Field(default=None, max_length=255)
    domain: str | None = Field(default=None, max_length=255)    # AD domain e.g. "ACME.LOCAL" or "ACME"
    password: str | None = Field(default=None, max_length=1024)  # plaintext at input, encrypted before storage
    extra: dict | None = None      # additional fields (community string, API key, etc.)
    save_to_vault: bool = False    # if True, also create a global Credential record
    vault_name: str | None = Field(default=None, max_length=255)  # name for vault entry if save_to_vault=True

    @field_validator("extra")
    @classmethod
    def _bound_extra(cls, v: dict | None) -> dict | None:
        """Cap the inline ``extra`` payload so a request can't bloat the DB."""
        if v is None:
            return v
        if len(v) > 20:
            raise ValueError("extra may contain at most 20 keys")
        for key, val in v.items():
            if len(str(key)) > 100:
                raise ValueError("extra key too long (max 100 chars)")
            if val is not None and len(str(val)) > 4096:
                raise ValueError("extra value too long (max 4096 chars)")
        return v


class ScanAiAgentConfig(BaseModel):
    """Opt-in AI agent configuration set at scan-creation time.

    When ``enabled``, the worker launches an AI agent run concurrently as the
    scan starts, so the AI investigates while the scan is in progress.
    """

    enabled: bool = False
    mode: str = Field(default="guided", pattern="^(guided|autonomous)$")
    objective: str = Field(default="", max_length=2000)
    provider: str | None = None
    model: str | None = None
    # Aggressive opt-ins — admin-only, each only takes effect with aggressive.
    aggressive: bool = False
    allow_privilege_escalation: bool = False
    allow_exploitation: bool = False
    allow_command_exec: bool = False

    def aggressive_requested(self) -> bool:
        return (
            self.aggressive
            or self.allow_privilege_escalation
            or self.allow_exploitation
            or self.allow_command_exec
        )


class ScanCreate(BaseModel):
    name: str
    description: str | None = None
    targets: list[str]               # raw target strings
    profile: str = "standard"        # quick | standard | full | custom
    profile_json: str | None = None
    credential_id: str | None = None          # keep for backward compat
    credentials: list[ScanCredentialIn] = []  # new: inline credentials
    exclusions: list[str] = []                # IPs/CIDRs/hosts to skip
    ai_agent: ScanAiAgentConfig | None = None  # opt-in AI agent auto-run


class ScanCredentialRead(BaseModel):
    id: str
    scan_id: str
    role: str
    type: str
    username: str | None
    domain: str | None
    vault_credential_id: str | None

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: str
    name: str
    status: str
    profile: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    hosts_total: int
    hosts_up: int
    findings_critical: int
    findings_high: int
    findings_medium: int
    findings_low: int
    findings_info: int
    error_message: str | None = None
    profile_json: str | None = None
    targets: list[str] = []
    ai_agent_enabled: bool = False
    ai_agent_mode: str | None = None

    model_config = {"from_attributes": True}

    @field_validator("targets", mode="before")
    @classmethod
    def _extract_target_values(cls, v):
        """Convert ORM Target objects to string values."""
        if v is None:
            return []
        if isinstance(v, list):
            return [t.value if hasattr(t, 'value') else str(t) for t in v]
        return v


class ScanRead(ScanSummary):
    description: str | None
    user_id: str

    model_config = {"from_attributes": True}
