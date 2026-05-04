from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ScanCredentialIn(BaseModel):
    """Inline credential provided at scan creation time."""

    role: str = "primary_domain"  # "primary_domain" | "local_admin" | "ssh" | "snmp" | "api" | "generic"
    type: str = "smb"             # credential type
    username: str | None = None
    domain: str | None = None     # AD domain e.g. "ACME.LOCAL" or "ACME"
    password: str | None = None   # plaintext at input, encrypted before storage
    extra: dict | None = None     # additional fields (community string, API key, etc.)
    save_to_vault: bool = False   # if True, also create a global Credential record
    vault_name: str | None = None  # name for vault entry if save_to_vault=True


class ScanCreate(BaseModel):
    name: str
    description: str | None = None
    targets: list[str]               # raw target strings
    profile: str = "standard"        # quick | standard | full | custom
    profile_json: str | None = None
    credential_id: str | None = None          # keep for backward compat
    credentials: list[ScanCredentialIn] = []  # new: inline credentials


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

    model_config = {"from_attributes": True}


class ScanRead(ScanSummary):
    description: str | None
    user_id: str

    model_config = {"from_attributes": True}
