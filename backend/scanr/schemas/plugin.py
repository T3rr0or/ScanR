from datetime import datetime

from pydantic import BaseModel


class PluginRead(BaseModel):
    id: str
    name: str
    description: str | None
    category: str
    default_severity: str
    enabled: bool
    requires_auth: bool
    cve_ids: str | None

    model_config = {"from_attributes": True}


class PluginUpdate(BaseModel):
    enabled: bool | None = None
    config_json: str | None = None


class PluginRunRead(BaseModel):
    id: str
    scan_id: str
    host_id: str | None
    plugin_id: str
    host_ip: str | None
    status: str
    duration_ms: int
    findings_count: int
    error: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PluginHealthRead(BaseModel):
    plugin_id: str
    total_runs: int
    success_count: int
    timeout_count: int
    error_count: int
    findings_count: int
    avg_duration_ms: int
    max_duration_ms: int
