"""End-of-life Python runtime detection.

Services announce their interpreter in a banner far more often than operators
expect — `SimpleHTTP/0.6 Python/3.6.9`, `Werkzeug/2.0.1 Python/3.7.9`, and most
`Server:` headers from Python HTTP stacks all carry it. A runtime past its
end-of-life date stops receiving security patches entirely, so every later CVE
in the interpreter (and in the stdlib TLS, XML and HTTP parsers it ships) stays
open regardless of how current the application on top of it is.

Passive: this reads banners the scan already collected and sends no traffic of
its own. Support windows are dates rather than a hand-maintained "is EOL" flag,
so the finding stays correct as releases age out without anyone editing it.
"""
from __future__ import annotations

import logging
import re
from datetime import date
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# python.org's published end-of-support dates, keyed by (major, minor). A series
# absent from this table is either newer than the table or unknown, and is not
# reported — guessing would produce false positives on fresh releases.
PYTHON_EOL: dict[tuple[int, int], date] = {
    (2, 0): date(2001, 6, 22),
    (2, 1): date(2002, 4, 9),
    (2, 2): date(2003, 5, 30),
    (2, 3): date(2004, 10, 19),
    (2, 4): date(2006, 12, 19),
    (2, 5): date(2008, 10, 6),
    (2, 6): date(2013, 10, 29),
    (2, 7): date(2020, 1, 1),
    (3, 0): date(2009, 6, 27),
    (3, 1): date(2012, 4, 9),
    (3, 2): date(2016, 2, 20),
    (3, 3): date(2017, 9, 29),
    (3, 4): date(2019, 3, 18),
    (3, 5): date(2020, 9, 30),
    (3, 6): date(2021, 12, 23),
    (3, 7): date(2023, 6, 27),
    (3, 8): date(2024, 10, 7),
    (3, 9): date(2025, 10, 31),
    (3, 10): date(2026, 10, 31),
    (3, 11): date(2027, 10, 31),
    (3, 12): date(2028, 10, 31),
    (3, 13): date(2029, 10, 31),
    (3, 14): date(2030, 10, 31),
}

# How far past end-of-life before the exposure is treated as more than stale.
_HIGH_AFTER_DAYS = 730   # ~2 years unpatched
_MEDIUM_AFTER_DAYS = 0   # any time past EOL
# Flag a still-supported series once its end-of-life is this close.
_APPROACHING_DAYS = 180

_VERSION_RE = re.compile(r"\bPython[/ ](\d+)\.(\d+)(?:\.(\d+))?", re.IGNORECASE)


def parse_python_version(text: str | None) -> tuple[int, int, str] | None:
    """Return (major, minor, full_version) for a Python version in `text`."""
    if not text:
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    major, minor = int(match.group(1)), int(match.group(2))
    patch = match.group(3)
    full = f"{major}.{minor}" + (f".{patch}" if patch else "")
    return major, minor, full


def assess(major: int, minor: int, today: date) -> tuple[Severity, int] | None:
    """Classify a Python series, or None when it needs no finding.

    Returns the severity and the number of days past end-of-life (negative when
    the date is still in the future).
    """
    eol = PYTHON_EOL.get((major, minor))
    if eol is None:
        return None
    days_past = (today - eol).days
    if days_past >= _HIGH_AFTER_DAYS:
        return Severity.high, days_past
    if days_past >= _MEDIUM_AFTER_DAYS:
        return Severity.medium, days_past
    if days_past >= -_APPROACHING_DAYS:
        return Severity.low, days_past
    return None


class PythonEolPlugin(PluginBase):
    id = "services.python_eol"
    name = "End-of-Life Python Runtime"
    description = "Flag services running a Python interpreter past its end-of-life date"
    category = PluginCategory.services
    severity = Severity.medium
    ports = None

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        today = date.today()
        findings: list[FindingData] = []
        # One finding per distinct series per host: the same interpreter usually
        # backs several ports, and repeating it buries the rest of the report.
        seen: set[tuple[int, int]] = set()

        for port in host.ports:
            if port.state != "open":
                continue
            for source in self._version_sources(port):
                parsed = parse_python_version(source)
                if parsed is None:
                    continue
                major, minor, full = parsed
                if (major, minor) in seen:
                    break
                verdict = assess(major, minor, today)
                if verdict is None:
                    break
                seen.add((major, minor))
                findings.append(
                    self._build_finding(major, minor, full, source, verdict, port.number)
                )
                break
        return findings

    @staticmethod
    def _version_sources(port) -> list[str]:
        """Places a port may advertise its interpreter, most specific first."""
        sources = [port.banner]
        service = getattr(port, "service", None)
        if service is not None:
            sources.extend([service.product, service.version, service.extra_info])
        return [s for s in sources if s]

    def _build_finding(
        self,
        major: int,
        minor: int,
        full: str,
        evidence_source: str,
        verdict: tuple[Severity, int],
        port_number: int,
    ) -> FindingData:
        severity, days_past = verdict
        series = f"{major}.{minor}"
        eol = PYTHON_EOL[(major, minor)]

        if days_past >= 0:
            title = f"End-of-Life Python Runtime ({series})"
            state = (
                f"Python {series} reached end of life on {eol.isoformat()}, "
                f"{days_past // 365} year(s) and {days_past % 365 // 30} month(s) ago. "
                "It receives no security patches, so every interpreter and standard "
                "library vulnerability disclosed since then remains unfixed."
            )
        else:
            title = f"Python Runtime Approaching End of Life ({series})"
            state = (
                f"Python {series} reaches end of life on {eol.isoformat()}, in "
                f"{-days_past} days. After that it receives no security patches."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=title,
            description=(
                f"The service advertises Python {full}. {state}"
            ),
            evidence=f"Detected from service banner: {evidence_source[:300]}",
            remediation=(
                "Upgrade to a Python series still receiving security support. "
                "If the runtime is pinned by a dependency, rebuild the service image "
                "on a supported base (for example python:3.13-slim) and retest. "
                "Where an immediate upgrade is not possible, restrict network exposure "
                "of this service and track the interpreter in your risk register."
            ),
            references=[
                "https://devguide.python.org/versions/",
                "https://endoflife.date/python",
            ],
            port_number=port_number,
            protocol="tcp",
        )
