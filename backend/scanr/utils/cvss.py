"""CVSS v3.1 score calculator from vector string."""
from __future__ import annotations

import math

# Metric weights per CVSS v3.1 spec
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_S = {"U": 0, "C": 1}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_E = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}
_RL = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}
_RC = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}


def _roundup(x: float) -> float:
    return math.ceil(x * 10) / 10


def calculate_cvss3(vector: str) -> float | None:
    """Return base score (0.0-10.0) from a CVSS v3.x vector string, or None on error."""
    try:
        parts = vector.split("/")
        metrics: dict[str, str] = {}
        for part in parts[1:]:
            k, v = part.split(":")
            metrics[k] = v

        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        scope_changed = metrics["S"] == "C"
        pr = _PR_CHANGED[metrics["PR"]] if scope_changed else _PR_UNCHANGED[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        exploitability = 8.22 * av * ac * pr * ui

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        if impact <= 0:
            return 0.0

        if scope_changed:
            base = _roundup(min(1.08 * (impact + exploitability), 10))
        else:
            base = _roundup(min(impact + exploitability, 10))

        return base
    except (KeyError, ValueError, IndexError):
        return None


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"
