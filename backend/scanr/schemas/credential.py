from pydantic import BaseModel


class CredentialCreate(BaseModel):
    name: str
    type: str            # ssh | wmi | snmp | http_basic | http_form | ftp | smb
    username: str | None = None
    description: str | None = None
    # Raw secret data — encrypted before storage, never returned
    secret_data: dict   # e.g. {"password": "..."} or {"private_key": "..."}


class CredentialRead(BaseModel):
    id: str
    name: str
    type: str
    username: str | None
    description: str | None
    # NOTE: secret_data is intentionally omitted

    model_config = {"from_attributes": True}
