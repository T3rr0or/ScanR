from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from scanr.core.scan_logger import ScanLogger
from scanr.models import Scan


@dataclass
class ScanContext:
    """Shared state for a single scan run — passed to every plugin."""
    scan_id: str
    scan: Scan
    db: AsyncSession
    profile: str = "standard"
    credential_data: dict | None = None  # decrypted from vault if provided (legacy single-credential)
    scan_credentials: list[dict] = field(default_factory=list)
    # scan_credentials entries: {"role": str, "type": str, "username": str, "domain": str, "password": str, ...}

    # Cancellation support
    cancelled: bool = False
    _cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    # Progress counters (updated by engine/plugins)
    hosts_discovered: int = 0
    hosts_scanned: int = 0
    findings_count: int = 0

    # Live log emitter (initialised by engine)
    log: ScanLogger = field(default_factory=lambda: ScanLogger(""))

    def __post_init__(self) -> None:
        # Ensure logger has the correct scan_id even if default_factory ran first
        if not self.log.scan_id:
            self.log = ScanLogger(self.scan_id)

    def request_cancel(self) -> None:
        self.cancelled = True
        self._cancel_event.set()

    def check_cancelled(self) -> None:
        if self.cancelled:
            raise asyncio.CancelledError("Scan cancelled")

    def credential(self, role: str) -> dict | None:
        """Return first scan-scoped credential matching role, or fall back to credential_data."""
        for c in self.scan_credentials:
            if c.get("role") == role:
                return c
        # Backward compat: if old single credential_data exists and role is a generic match
        if self.credential_data and role in ("primary_domain", "generic", "smb", "ssh"):
            return self.credential_data
        return None

    def has_credential(self, role: str) -> bool:
        return self.credential(role) is not None

    def get_port_range(self) -> str:
        """Return nmap port spec based on profile, with profile_json override support."""
        import json as _json
        if self.scan.profile_json:
            try:
                pj = _json.loads(self.scan.profile_json) if isinstance(self.scan.profile_json, str) else self.scan.profile_json
                custom = pj.get("port_range")
                if custom:
                    if custom == "top-1000":
                        return "--top-ports 1000"
                    if custom == "top-10000":
                        return "--top-ports 10000"
                    if custom == "all":
                        return "-p-"
                    # Custom spec like "80,443" or "1-1024"
                    return f"-p {custom}"
            except Exception:
                pass
        match self.profile:
            case "quick":
                return "--top-ports 1000"
            case "standard":
                return "--top-ports 10000"
            case "full":
                return "-p-"
            case _:
                return "--top-ports 10000"
