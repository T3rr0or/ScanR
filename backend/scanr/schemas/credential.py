from typing import Literal
from pydantic import BaseModel, Field

_CRED_TYPES = Literal["ssh", "wmi", "snmp", "http_basic", "http_form", "ftp", "smb"]


class CredentialCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: _CRED_TYPES
    username: str | None = Field(None, max_length=255)
    description: str | None = Field(None, max_length=1000)
    secret_data: dict = Field(..., description="Encrypted before storage — never returned")


class CredentialRead(BaseModel):
    id: str
    name: str
    type: str
    username: str | None
    description: str | None
    # NOTE: secret_data is intentionally omitted

    model_config = {"from_attributes": True}
