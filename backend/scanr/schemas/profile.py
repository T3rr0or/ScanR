"""Validated schema for a scan's ``profile_json``.

``profile_json`` is operator-supplied JSON that the scan engine turns into
scanner arguments — most notably ``port_range``, which reaches nmap's argument
list. It therefore MUST be validated on every path that can persist it, not
just on scan creation:

  * ``POST/PATCH /scans``    — the scan itself
  * ``POST/PUT  /schedules`` — copied verbatim into a Scan at fire time
  * ``POST/PUT  /templates`` — offered to the UI as scan defaults

An unvalidated ``port_range`` is an argument-injection sink: ``get_port_range()``
renders it as ``-p {value}``, and python-nmap runs ``shlex.split()`` over the
argument string, so whitespace in the value becomes additional nmap flags
(``--script``, ``-oN``, …). Keeping the model here — rather than private to the
scans router — is what stops a new writer from silently skipping the check.
"""
from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

__all__ = [
    "ProfileJson",
    "is_safe_port_range",
    "validate_profile_json",
    "validate_profile_dict",
]

# Accepts only nmap-safe port specs: 'top-N', 'all', or comma-separated
# ports/ranges. Deliberately has no whitespace class — whitespace is exactly
# what would let a value inject extra nmap arguments.
_PORT_RANGE_RE = re.compile(
    r'^(top-\d{1,5}|all|[1-9]\d{0,4}(-[1-9]\d{0,4})?(,[1-9]\d{0,4}(-[1-9]\d{0,4})?)*)$'
)


def is_safe_port_range(value: object) -> bool:
    """True if ``value`` is a port spec safe to interpolate into scanner argv.

    Used both by the API schema and by the scan engine at the point of use, so a
    profile that reached the database without passing the schema still cannot
    inject scanner arguments.
    """
    if not isinstance(value, str) or not _PORT_RANGE_RE.match(value):
        return False
    if value.startswith("top-") and int(value[4:]) > 65535:
        return False
    return True


class BruteForceConfig(BaseModel):
    enabled: bool = False
    credential_wordlist_id: str | None = None
    username_wordlist_id: str | None = None
    password_wordlist_id: str | None = None
    max_concurrent: int = Field(default=3, ge=1, le=20)
    delay_ms: int = Field(default=500, ge=0, le=30000)
    stop_on_success: bool = False
    max_failures_per_account: int = Field(default=5, ge=1, le=100)


class DiscoveryConfig(BaseModel):
    icmp: bool = True
    tcp: bool = True
    arp: bool = True
    udp: bool = False
    retries: int = Field(default=1, ge=0, le=10)
    strategy: Literal["fast", "validated"] = "validated"
    mode: Literal["fast", "aggressive", "skip"] = "fast"
    assume_up: bool = False


ScannerName = Literal["tcp_connect", "syn", "udp"]


def _default_scanners() -> list[ScannerName]:
    return ["tcp_connect"]


class PortScanningConfig(BaseModel):
    scanner: ScannerName | None = None
    scanners: list[ScannerName] = Field(default_factory=_default_scanners)
    firewall_strategy: Literal["default", "skip_ping"] = "default"
    timing: int = Field(default=4, ge=1, le=5)

    @field_validator("scanners", mode="before")
    @classmethod
    def _normalize_scanners(cls, v, info):
        """Accept old single-string 'scanner' field or new 'scanners' array.
        An explicitly-empty array means no port scanning."""
        if v is not None:
            return v
        old = info.data.get("scanner")
        if old:
            return [old]
        return ["tcp_connect"]


class EnumerationConfig(BaseModel):
    service_detection: bool = True
    http_probing: bool = True
    tls_checks: bool = True
    security_headers: bool = True
    screenshots: bool = True
    nuclei: bool = True
    directory_enum: bool = False
    subdomain_enum: bool = False
    dns_recon: bool = False


class PerformanceConfig(BaseModel):
    max_concurrent_hosts: int = Field(default=20, ge=1, le=200)
    max_concurrent_plugins: int = Field(default=20, ge=1, le=100)
    timeout: int = Field(default=60, ge=1, le=3600)
    masscan_rate: int = Field(default=10000, ge=1, le=100000)
    nuclei_rate: int = Field(default=25, ge=1, le=1000)
    max_hosts: int | None = Field(default=None, ge=1, le=65536)
    max_checks: int | None = Field(default=None, ge=1, le=1000000)


class ProfileJson(BaseModel):
    target_mode: Literal["internal", "domain", "bug_bounty", "external"] | None = None
    scan_context: Literal["internal", "external", "custom"] | None = None
    target_type: Literal["ip", "cidr", "range", "hostname", "domain"] | None = None
    safety_level: Literal["safe", "balanced", "aggressive"] | None = None
    depth_level: Literal["light", "balanced", "deep"] | None = None
    performance_profile: Literal["conservative", "normal", "fast", "custom"] | None = None
    external_recon: bool = False
    subdomain_enum: bool = True
    max_subdomains: int | None = Field(default=None, ge=0, le=1000)
    disable_masscan: bool = False
    allow_full_port_scan: bool = False
    port_range: str | None = None
    masscan_rate: int | None = Field(default=None, ge=1, le=100000)
    plugins: list[str] | None = None
    timeout: int | None = Field(default=None, ge=1, le=3600)
    max_concurrent: int | None = Field(default=None, ge=1, le=100)
    intrusive: bool = False
    debug: bool = False
    stealth: bool = False
    credential_chain: bool = False
    xxe_probe_file: str | None = Field(default=None, max_length=200)
    discovery: DiscoveryConfig | None = None
    port_scanning: PortScanningConfig | None = None
    enumeration: EnumerationConfig | None = None
    performance: PerformanceConfig | None = None
    brute_force: BruteForceConfig | None = None

    @field_validator("port_range")
    @classmethod
    def _check_port_range(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _PORT_RANGE_RE.match(v):
            raise ValueError(
                f"Invalid port_range: {v!r}. Use e.g. 'top-1000', '80,443', '1-1024', 'all'."
            )
        if v.startswith("top-") and int(v[4:]) > 65535:
            raise ValueError(f"{v} exceeds nmap maximum of 65535")
        return v


def validate_profile_dict(data: object, *, field: str = "profile_json") -> dict:
    """Validate an already-parsed profile mapping. Raises ValueError on reject."""
    if not isinstance(data, dict):
        raise ValueError(f"{field} must be a JSON object")
    try:
        validated = ProfileJson.model_validate(data)
    except Exception as exc:
        raise ValueError(f"Invalid {field}: {exc}") from exc
    return json.loads(validated.model_dump_json(exclude_none=True))


def validate_profile_json(raw: str, *, field: str = "profile_json") -> str:
    """Validate a raw JSON string and return its normalized serialization."""
    try:
        parsed = json.loads(raw)
    except Exception as exc:
        raise ValueError(f"{field} is not valid JSON") from exc
    return json.dumps(validate_profile_dict(parsed, field=field))
