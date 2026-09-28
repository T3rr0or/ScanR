"""Shared fingerprinting for HTTP-fronted platforms.

Several service checks answer the same two questions about a product reachable
over HTTP: is it this product, and does it return data without authentication.
Getting the second one right is the part worth writing once — these platforms
routinely answer an unauthenticated API call with a 200 carrying a login page or
an empty envelope, so a status code alone is not evidence. A probe therefore
declares the markers its response must contain, and only a reply carrying all of
them counts as access.

Used by ``services.devops_platform_exposure`` and ``services.db_extended_unauth``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from scanr.core.plugin_base import Severity
from scanr.plugins.services._pentest_common import _http_get

__all__ = [
    "AnonProbe",
    "ConfirmedAccess",
    "HttpPlatform",
    "SEVERITY_RANK",
    "anon_access_confirmed",
    "extract_version",
    "highest_severity",
    "identifies",
    "probe_anonymous",
    "identify_platform",
]

MAX_BODY = 200_000
EVIDENCE_SNIPPET = 300

SEVERITY_RANK: dict[Severity, int] = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


@dataclass(frozen=True)
class AnonProbe:
    """An endpoint whose success proves unauthenticated access to real data."""

    path: str
    required_markers: tuple[str, ...]
    severity: Severity
    meaning: str


@dataclass(frozen=True)
class HttpPlatform:
    """One product: how to recognise it, and what proves anonymous access."""

    name: str
    ports: tuple[int, ...]
    identify_paths: tuple[str, ...]
    identify_markers: tuple[str, ...]
    anon_probes: tuple[AnonProbe, ...] = ()
    version_patterns: tuple[re.Pattern[str], ...] = ()
    impact: str = ""
    remediation: str = ""
    reference: str = ""
    notable_cves: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConfirmedAccess:
    """A probe that came back with the data it was supposed to protect."""

    probe: AnonProbe
    url: str
    snippet: str


def identifies(
    platform: HttpPlatform, body: str, headers: dict[str, str]
) -> list[str]:
    """Reasons this response identifies `platform`. Empty means no match."""
    reasons: list[str] = []
    lowered = body[:MAX_BODY].lower()
    header_blob = " ".join(f"{key}: {value}" for key, value in headers.items()).lower()
    for marker in platform.identify_markers:
        needle = marker.lower()
        if needle in lowered:
            reasons.append(f"body contains {marker!r}")
        elif needle in header_blob:
            reasons.append(f"response header contains {marker!r}")
    return reasons


def anon_access_confirmed(probe: AnonProbe, status: int, body: str) -> bool:
    """True only when the endpoint returned the data it is supposed to protect."""
    if status != 200:
        return False
    lowered = body[:MAX_BODY].lower()
    return all(marker.lower() in lowered for marker in probe.required_markers)


def extract_version(platform: HttpPlatform, text: str) -> str:
    for pattern in platform.version_patterns:
        match = pattern.search(text.strip())
        if match:
            return match.group(1)
    return ""


def highest_severity(accesses: list[ConfirmedAccess]) -> Severity:
    return max(
        (access.probe.severity for access in accesses),
        key=lambda level: SEVERITY_RANK[level],
    )


async def identify_platform(
    context, ip: str, port: int, platform: HttpPlatform
) -> tuple[list[str], str, str] | None:
    """(reasons, version, url) for the first path that identifies the platform."""
    for path in platform.identify_paths:
        fetched = await _http_get(context, ip, port, path, https=None)
        if fetched is None:
            continue
        url, response = fetched
        body = response.text or ""
        reasons = identifies(platform, body, dict(response.headers))
        if reasons:
            return reasons, extract_version(platform, body), url
    return None


async def probe_anonymous(
    context, ip: str, port: int, platform: HttpPlatform
) -> list[ConfirmedAccess]:
    """Every probe whose response confirms unauthenticated access."""
    confirmed: list[ConfirmedAccess] = []
    for probe in platform.anon_probes:
        fetched = await _http_get(context, ip, port, probe.path, https=None)
        if fetched is None:
            continue
        url, response = fetched
        body = response.text or ""
        if anon_access_confirmed(probe, response.status_code, body):
            confirmed.append(
                ConfirmedAccess(probe=probe, url=url, snippet=body[:EVIDENCE_SNIPPET])
            )
    return confirmed
