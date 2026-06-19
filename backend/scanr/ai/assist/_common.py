"""Shared helpers for assist features — compact, severity-sorted, fenced
finding blocks kept small enough to control token cost.

Finding text is influenced by scanned hosts; callers fence it and the system
prompts instruct the model to treat it as untrusted data, never instructions.
"""
from __future__ import annotations

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
DEFAULT_MAX_FINDINGS = 200
_MAX_DESC = 240
_MAX_EVIDENCE = 400


def rank(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get((f.get("severity") or "info").lower(), 4))


def _where(f: dict) -> str:
    host = f.get("host_ip") or f.get("host_id") or "-"
    port = f.get("port_number")
    return f"{host}:{port}" if port else str(host)


def _truncate(text: str, limit: int) -> str:
    text = (text or "").replace("\n", " ").strip()
    return text[:limit] + "…" if len(text) > limit else text


def finding_line(f: dict, *, include_id: bool = False, include_evidence: bool = False) -> str:
    sev = (f.get("severity") or "info").upper()
    title = (f.get("title") or "").replace("\n", " ").strip()
    prefix = f"[{f.get('id')}] " if include_id else ""
    cvss = f.get("cvss_score")
    cvss_s = f" cvss={cvss}" if cvss else ""
    line = f"- {prefix}[{sev}] {title} @ {_where(f)}{cvss_s}"
    desc = _truncate(f.get("description") or "", _MAX_DESC)
    if desc:
        line += f"\n    desc: {desc}"
    if include_evidence:
        ev = _truncate(f.get("evidence") or "", _MAX_EVIDENCE)
        if ev:
            line += f"\n    evidence: {ev}"
    return line


def fenced_block(
    findings: list[dict],
    *,
    include_id: bool = False,
    include_evidence: bool = False,
    max_findings: int = DEFAULT_MAX_FINDINGS,
) -> tuple[str, int]:
    """Return (fenced findings block, number shown). Untrusted data is wrapped
    in <findings> tags so the model can be told to treat it strictly as data."""
    ranked = rank(findings)
    shown = ranked[:max_findings]
    rows = "\n".join(
        finding_line(f, include_id=include_id, include_evidence=include_evidence) for f in shown
    )
    omitted = len(ranked) - len(shown)
    header = f"Findings ({len(findings)} total"
    header += f", showing top {len(shown)} by severity)" if omitted > 0 else ")"
    return f"{header}:\n\n<findings>\n{rows}\n</findings>", len(shown)
