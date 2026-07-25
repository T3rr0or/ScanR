"""Re-run the plugin behind a finding and decide whether it is still there.

The gap this closes: ScanR could tell you a finding was new, persisting or gone
*between two full scans*, but there was no way to ask "is this specific issue
fixed yet" without re-running the whole thing. On a remediation cycle that is the
question being asked over and over.

The comparison logic lives here, separate from the Celery task and the API, so it
can be tested without a broker or a database.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

__all__ = ["RetestOutcome", "decide_verdict", "summarise_observations"]


@dataclass(frozen=True)
class RetestOutcome:
    verdict: str
    evidence: str


def _norm(value: object) -> str:
    return " ".join(str(value or "").split()).strip().lower()


def _matches(original_title: str, original_port: int | None, observed: dict) -> bool:
    """Does an observed finding correspond to the original one?

    Same plugin is already guaranteed by construction — the retest re-runs that
    one plugin against that one host. What remains is distinguishing *which*
    result: a plugin can report several findings for a host (three weak ciphers,
    two default accounts), and only the matching one tells us anything about this
    finding.

    Title is the discriminator, with the port as a tiebreak when the plugin
    reports per-port. Exact title equality is too brittle — titles often embed the
    port or a version — so a containment match either way is used.
    """
    o_title = _norm(original_title)
    n_title = _norm(observed.get("title"))
    if not n_title or not o_title:
        return False

    if original_port is not None and observed.get("port_number") is not None:
        if int(observed["port_number"]) != int(original_port):
            return False

    return o_title == n_title or o_title in n_title or n_title in o_title


def decide_verdict(
    *,
    original_title: str,
    original_port: int | None,
    observations: list[dict],
    host_reachable: bool = True,
) -> RetestOutcome:
    """Compare a re-run's output against the original finding.

    Conservative by design. "Resolved" is a claim a client acts on — they close
    the ticket — so it is only returned when the plugin ran against a reachable
    host and reported nothing matching. An unreachable host is *inconclusive*, not
    fixed: a box that is merely switched off during the retest window has not been
    remediated, and reporting otherwise is how a real vulnerability gets closed.
    """
    if not host_reachable:
        return RetestOutcome(
            verdict="inconclusive",
            evidence=(
                "Host did not respond during the retest, so the check could not run. "
                "This is not evidence of remediation — re-run when the host is up."
            ),
        )

    matched = [o for o in observations if _matches(original_title, original_port, o)]
    if matched:
        return RetestOutcome(
            verdict="still_present",
            evidence=summarise_observations(matched),
        )

    if observations:
        # The plugin found *something*, just not this. Worth saying so: it means
        # the check genuinely ran, which makes "resolved" much stronger evidence.
        return RetestOutcome(
            verdict="resolved",
            evidence=(
                "The check ran and no longer reports this issue. It did report "
                f"{len(observations)} other finding(s) on this host, so the plugin "
                "was working:\n" + summarise_observations(observations)
            ),
        )

    return RetestOutcome(
        verdict="resolved",
        evidence="The check ran against the host and reported nothing.",
    )


def summarise_observations(observations: list[dict], limit: int = 5) -> str:
    """Human-readable digest of what the re-run saw."""
    lines = []
    for o in observations[:limit]:
        severity = str(o.get("severity") or "?")
        title = str(o.get("title") or "(untitled)")
        port = o.get("port_number")
        suffix = f" (port {port})" if port else ""
        lines.append(f"- [{severity}] {title}{suffix}")
        evidence = str(o.get("evidence") or "").strip()
        if evidence:
            lines.append(f"    {evidence[:300]}")
    if len(observations) > limit:
        lines.append(f"- … and {len(observations) - limit} more")
    return "\n".join(lines)
