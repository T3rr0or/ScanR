from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from scanr.core.scan_logger import ScanLogger
from scanr.core.rate_limiter import RateLimiter
from scanr.models import Scan


@dataclass
class ScanContext:
    """Shared state for a single scan run — passed to every plugin."""
    scan_id: str
    scan: Scan
    db: AsyncSession
    profile: str = "standard"
    credential_data: dict | None = None  # decrypted from vault if provided
    credentials_by_role: dict[str, dict] = field(default_factory=dict)
    credentials: list[dict] = field(default_factory=list)
    stealth_mode: bool = False
    discovered_credentials: list = field(default_factory=list)  # in-memory only, never persisted
    rate_limiter: RateLimiter | None = None

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

    # AsyncSession is not safe for concurrent task use. The engine scans hosts
    # and plugins concurrently, so DB reads/writes must share this lock.
    db_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        # Ensure logger has the correct scan_id even if default_factory ran first
        if not self.log.scan_id:
            self.log = ScanLogger(self.scan_id)

    # Pause support
    _paused: bool = field(default=False)
    _pause_event: asyncio.Event = field(default_factory=asyncio.Event)

    def request_pause(self) -> None:
        self._paused = True

    def request_resume(self) -> None:
        self._paused = False
        self._pause_event.set()
        self._pause_event.clear()

    async def wait_if_paused(self) -> None:
        while self._paused and not self.cancelled:
            await asyncio.sleep(1.0)

    def request_cancel(self) -> None:
        self.cancelled = True
        self._paused = False  # unpause so the loop can exit
        self._cancel_event.set()

    def check_cancelled(self) -> None:
        if self.cancelled:
            raise asyncio.CancelledError("Scan cancelled")

    def store_credential(self, cred_type: str, username: str, password: str | None = None, **extra) -> None:
        """Store a discovered credential for the credential chaining phase."""
        self.discovered_credentials.append({
            "type": cred_type, "username": username, "password": password,
            **extra
        })

    def credential(self, role: str) -> dict | None:
        """Return credential data for the given role. Falls back to primary credential."""
        if role in self.credentials_by_role:
            return self.credentials_by_role[role]
        if role == "generic" and self.credentials:
            return self.credentials[0]
        return self.credential_data

    def web_auth_headers(self) -> dict[str, str]:
        """Return auth headers (Cookie, Authorization) from scan credentials.

        Scans all credentials for web-relevant types:
          - http_basic: Authorization: Basic ...
          - bearer_token: Authorization: Bearer ...
          - Cookie from extra['cookies']
        """
        headers: dict[str, str] = {}
        for cred_data in self.credentials:
            cred_type = cred_data.get("type", "").lower()
            username = cred_data.get("username", "")
            password = cred_data.get("secret", "") or cred_data.get("password", "")
            extra = cred_data.get("extra", {}) or {}

            if cred_type in ("http_basic",):
                import base64
                token = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {token}"
            elif cred_type in ("bearer_token",) and password:
                headers["Authorization"] = f"Bearer {password}"

            cookies = extra.get("cookies") or extra.get("cookie") or extra.get("session_cookie")
            if cookies:
                existing = headers.get("Cookie", "")
                headers["Cookie"] = f"{existing}; {cookies}".strip("; ")

        # Also check the legacy primary credential data
        cd = self.credential_data
        if cd:
            ct = cd.get("type", "").lower()
            if ct in ("http_basic",) and cd.get("username"):
                import base64
                token = base64.b64encode(f"{cd['username']}:{cd.get('password', '')}".encode()).decode()
                if "Authorization" not in headers:
                    headers["Authorization"] = f"Basic {token}"
            if ct in ("bearer_token",) and cd.get("password") and "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {cd['password']}"

        return headers

    def get_brute_config(self) -> dict:
        """Return brute_force config from profile_json, with safe defaults."""
        defaults = {
            "credential_wordlist_id": None,
            "username_wordlist_id": None,
            "password_wordlist_id": None,
            "max_concurrent": 3,
            "delay_ms": 500,
            "stop_on_success": False,
            "max_failures_per_account": 5,
        }
        cfg = self.profile_json().get("brute_force", {})
        return {**defaults, **cfg}

    def profile_json(self) -> dict:
        """Return parsed scan profile_json, or an empty object on invalid input."""
        import json as _json
        if not self.scan.profile_json:
            return {}
        try:
            return _json.loads(self.scan.profile_json) if isinstance(self.scan.profile_json, str) else self.scan.profile_json
        except Exception:
            return {}

    def performance_config(self) -> dict:
        pj = self.profile_json()
        perf = pj.get("performance") or {}
        return {
            "max_concurrent_hosts": int(perf.get("max_concurrent_hosts") or pj.get("max_concurrent") or 20),
            "max_concurrent_plugins": int(perf.get("max_concurrent_plugins") or 20),
            "timeout": int(perf.get("timeout") or pj.get("timeout") or 60),
            "masscan_rate": int(perf.get("masscan_rate") or pj.get("masscan_rate") or 10000),
            "nuclei_rate": int(perf.get("nuclei_rate") or 25),
            "max_hosts": perf.get("max_hosts"),
            "max_checks": perf.get("max_checks"),
        }

    def discovery_config(self) -> dict:
        pj = self.profile_json()
        cfg = pj.get("discovery") or {}
        scan_context = pj.get("scan_context") or pj.get("target_mode")
        target_type = pj.get("target_type")
        external_domain = scan_context in {"external", "domain", "bug_bounty"} or target_type == "domain"
        return {
            "icmp": bool(cfg.get("icmp", not external_domain)),
            "tcp": bool(cfg.get("tcp", True)),
            "arp": bool(cfg.get("arp", scan_context == "internal")),
            "udp": bool(cfg.get("udp", False)),
            "retries": int(cfg.get("retries", 1)),
            "strategy": cfg.get("strategy", "fast" if external_domain else "validated"),
            "mode": cfg.get("mode", "fast"),
            "assume_up": bool(cfg.get("assume_up", False)),
        }

    def port_scanning_config(self) -> dict:
        pj = self.profile_json()
        cfg = pj.get("port_scanning") or {}
        scanners = cfg.get("scanners") or []
        if not scanners and cfg.get("scanner"):
            scanners = [cfg["scanner"]]
        return {
            "scanners": scanners,
            "firewall_strategy": cfg.get("firewall_strategy", "default"),
            "timing": int(cfg.get("timing", 4)),
        }

    def proxy_config(self) -> dict:
        """Return httpx-compatible proxy kwargs for HTTP plugins."""
        from scanr.utils.proxy import get_proxy_config
        return get_proxy_config()

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
        pj = self.profile_json()
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
        match self.profile:
            case "quick":
                return "--top-ports 1000"
            case "standard":
                return "--top-ports 10000"
            case "full":
                return "-p-"
            case _:
                return "--top-ports 10000"
