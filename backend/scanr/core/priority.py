""""Fix first" priority: one 0-100 number per finding, with its reasons.

Severity alone ranks a theoretical critical above a medium that attackers are
exploiting today on an internet-facing box. The score adds up three parts:

* Impact, 0-40: CVSS x 4, or a severity-based stand-in when there is no CVSS.
* Exploitation, 0-40: the strongest of
    - listed in CISA KEV (known exploited)      -> 40
    - ScanR reproduced it (validated)           -> 35
    - EPSS probability p                        -> 40 x sqrt(p)
    - nothing known                             -> 12 (about EPSS 9%)
* Exposure, 0-20: the host has a public IP address, or is tagged
  ``crown-jewel`` / ``critical``. Scaled by impact (20 x sqrt(impact / 40)),
  so exposure amplifies serious issues instead of lifting a missing header
  above an internal critical.

Informational findings are capped at 10. Every point is explained in
``reasons`` so the number is never a black box.
"""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field

CRITICAL_ASSET_TAGS = frozenset({"crown-jewel", "critical"})

_SEVERITY_IMPACT = {"critical": 38.0, "high": 28.0, "medium": 18.0, "low": 8.0, "info": 0.0}
_UNKNOWN_EXPLOITATION = 12.0
_INFO_CAP = 10.0

BANDS = ((80, "fix now"), (60, "fix soon"), (40, "plan"), (0, "low"))


@dataclass
class Priority:
    score: float
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    reasons: list[str] = field(default_factory=list)


def _percent(p: float) -> str:
    if p >= 0.999:
        return ">99.9%"
    if 0 < p < 0.001:
        return "<0.1%"
    return f"{p:.1%}"


def band(score: float | None) -> str | None:
    if score is None:
        return None
    return next(label for threshold, label in BANDS if score >= threshold)


def is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def compute(
    *,
    severity: str,
    cvss_score: float | None,
    cve_ids: list[str] | None,
    epss: dict[str, tuple[float, float]],
    kev: frozenset[str] | set[str],
    validated: bool = False,
    host_ip: str | None = None,
    host_tags: set[str] | frozenset[str] = frozenset(),
) -> Priority:
    reasons: list[str] = []
    cves = [c.upper() for c in (cve_ids or [])]

    if cvss_score is not None:
        impact = max(0.0, min(cvss_score, 10.0)) * 4
        reasons.append(f"CVSS {cvss_score:g}")
    else:
        impact = _SEVERITY_IMPACT.get(severity, 0.0)
        reasons.append(f"{severity} severity")

    known = [(c, epss[c]) for c in cves if c in epss]
    best = max(known, key=lambda item: item[1][0]) if known else None
    kev_hits = [c for c in cves if c in kev]

    exploitation = _UNKNOWN_EXPLOITATION
    if best:
        exploitation = 40 * math.sqrt(best[1][0])
        reasons.append(f"EPSS {_percent(best[1][0])} chance of exploitation ({best[0]})")
    if validated:
        exploitation = max(exploitation, 35.0)
        reasons.append("reproduced by ScanR")
    if kev_hits:
        exploitation = 40.0
        reasons.append(f"known exploited (CISA KEV: {', '.join(kev_hits[:3])})")
    if not best and not validated and not kev_hits:
        reasons.append("no exploitation data")

    exposed = False
    tagged = sorted(CRITICAL_ASSET_TAGS & {t.lower() for t in host_tags})
    if is_public_ip(host_ip):
        exposed = True
        reasons.append("internet-facing host")
    if tagged:
        exposed = True
        reasons.append(f"host tagged {tagged[0]}")
    exposure = 20 * math.sqrt(impact / 40) if exposed else 0.0

    score = impact + exploitation + exposure
    if severity == "info":
        score = min(score, _INFO_CAP)
    return Priority(
        score=round(min(score, 100.0), 1),
        epss_score=best[1][0] if best else None,
        epss_percentile=best[1][1] if best else None,
        is_kev=bool(kev_hits),
        reasons=reasons,
    )
