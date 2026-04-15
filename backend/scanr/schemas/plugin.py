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
