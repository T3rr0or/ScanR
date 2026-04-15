from __future__ import annotations

from pydantic import BaseModel


class ServiceRead(BaseModel):
    name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    cpe: str | None

    model_config = {"from_attributes": True}


class PortRead(BaseModel):
    id: str
    number: int
    protocol: str
    state: str
    banner: str | None
    service: ServiceRead | None

    model_config = {"from_attributes": True}


class HostRead(BaseModel):
    id: str
    ip: str
    hostname: str | None
    mac_address: str | None
    os_name: str | None
    os_accuracy: int | None
    status: str
    ports: list[PortRead] = []

    model_config = {"from_attributes": True}
