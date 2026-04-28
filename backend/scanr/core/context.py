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
    credential_data: dict | None = None  # decrypted from vault if provided

    # Cancellation support
    cancelled: bool = False
    _cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    # Progress counters (updated by engine/plugins)
    hosts_discovered: int = 0
    hosts_scanned: int = 0
    findings_count: int = 0

    # Live log emitter (initialised by engine)
    log: ScanLogger = field(default_factory=lambda: ScanLogger(""))

    # Wordlist id → file path, populated by engine before plugins run
    _wordlist_paths: dict = field(default_factory=dict)

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
        """Return credential data for the given role. Falls back to primary credential."""
        return self.credential_data

    def get_brute_config(self) -> dict:
        """Return brute_force config from profile_json, with safe defaults."""
        import json as _json
        defaults = {
            "credential_wordlist_id": None,
            "username_wordlist_id": None,
            "password_wordlist_id": None,
            "max_concurrent": 3,
            "delay_ms": 500,
            "stop_on_success": False,
            "max_failures_per_account": 5,
        }
        if not self.scan.profile_json:
            return defaults
        try:
            pj = _json.loads(self.scan.profile_json) if isinstance(self.scan.profile_json, str) else self.scan.profile_json
            cfg = pj.get("brute_force", {})
            return {**defaults, **cfg}
        except Exception:
            return defaults

    def iter_wordlist(self, wordlist_id: str):
        """
        Yield lines from a wordlist file one at a time.
        Strips whitespace, skips empty lines and # comments.
        Returns empty iterator if wordlist_id not found.
        """
        import os as _os
        path = self._wordlist_paths.get(wordlist_id)
        if not path or not _os.path.exists(path):
            return
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line

    def iter_credential_pairs(self, wordlist_id: str):
        """
        Yield (username, password) tuples from a credentials wordlist.
        Format: user:password per line. Password may contain colons.
        """
        for line in self.iter_wordlist(wordlist_id):
            if ":" in line:
                user, _, pwd = line.partition(":")
                yield user, pwd
            else:
                yield line, ""

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
