from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host


class PluginCategory(str, Enum):
    network = "network"
    ssl_tls = "ssl_tls"
    web = "web"
    services = "services"
    ssh = "ssh"
    authenticated = "authenticated"
    cve = "cve"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


@dataclass
class FindingData:
    """Data returned by a plugin check — converted to DB Finding by result_collector."""
    plugin_id: str
    severity: Severity
    title: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cvss_vector: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    port_number: int | None = None
    protocol: str | None = None


class PluginBase(ABC):
    # Subclasses MUST set these
    id: str
    name: str
    description: str
    category: PluginCategory
    severity: Severity
    cvss_vector: str | None = None
    cve_ids: list[str] = []
    requires_auth: bool = False
    ports: list[int] | None = None  # None = applicable to all ports

    @abstractmethod
    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        """Run this plugin against one host. Return list of findings (empty = clean)."""

    def applies_to_port(self, port_number: int) -> bool:
        return self.ports is None or port_number in self.ports
