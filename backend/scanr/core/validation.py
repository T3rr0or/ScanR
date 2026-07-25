"""Deciding whether a finding was actually reproduced.

A scanner that reports what it *pattern-matched* buries the reader in maybes: a
reflected parameter, a version banner, a header that is usually wrong. The
expensive part of a pentest report is the analyst deciding which of those are
real. ScanR can settle a useful subset of them mechanically — drive a real
browser at the thing and see whether the payload executes — and record the
answer on the finding.

The rules live here, apart from the browser driver, for two reasons: they are
the part worth arguing about, and they must be testable without Chromium.

What counts as proof is deliberately narrow. A canary that merely appears in the
page proves reflection, which is not a vulnerability; a canary that reaches
``alert()`` proves script execution in the page's origin, which is. Anything the
browser could not load is ``inconclusive`` — never "not vulnerable", for the same
reason an unreachable host cannot be called remediated (see core/retest.py).
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

__all__ = [
    "VALIDATION_METHODS",
    "VERDICTS",
    "ValidationResult",
    "evaluate",
    "new_canary",
]

#: Verdicts, strongest first. Only ``proved`` sets Finding.validated.
VERDICTS = ("proved", "reflected", "not_reproduced", "inconclusive")

#: Recorded on the finding so a reader knows *how* it was proved, not just that
#: something claimed it was. Extend as new proof channels are added.
VALIDATION_METHODS = ("browser-dialog", "browser-console")

# A canary must be unguessable (so a page can't fake one), and survive a round
# trip through HTML/JS/URL encoding untouched — hence letters and digits only.
_CANARY_RE = re.compile(r"^scanr[0-9a-f]{16}$")

#: At least one of these must be present for the dict to count as a real attempt.
_OBSERVATION_KEYS = {"dialogs", "console", "page_errors", "canary_in_dom", "error", "status"}


def new_canary() -> str:
    """A unique marker for one validation attempt.

    Per-attempt rather than fixed: a target that once saw the token cannot
    replay it later to manufacture a proof, and two concurrent attempts can't be
    confused for one another.
    """
    return "scanr" + secrets.token_hex(8)


@dataclass(frozen=True)
class ValidationResult:
    verdict: str
    method: str | None
    summary: str
    evidence: str

    @property
    def proved(self) -> bool:
        return self.verdict == "proved"


def evaluate(observations: dict, canary: str) -> ValidationResult:
    """Turn what the browser saw into a verdict.

    ``observations`` is whatever core/browser.py captured: dialogs, console
    messages, page errors, whether the canary reached the DOM, and any load
    error. Tolerant of a partial dict — a driver that captured less than usual
    should degrade to ``inconclusive``, not raise.
    """
    # A dict with none of the observation keys means the driver reported nothing,
    # which is a failure to look — not a look that found nothing.
    if not isinstance(observations, dict) or not (
        _OBSERVATION_KEYS & set(observations)
    ):
        return ValidationResult("inconclusive", None, "no observations captured", "")
    if not _CANARY_RE.match(str(canary or "")):
        # Refusing an arbitrary needle keeps "proof" meaning one thing: a token
        # this run generated. A caller-supplied string could match page content
        # that was never under our control.
        return ValidationResult(
            "inconclusive", None, "validation needs a canary issued by new_canary()", ""
        )

    if observations.get("error"):
        return ValidationResult(
            "inconclusive",
            None,
            f"could not load the page: {observations['error']}",
            _render_evidence(observations),
        )

    # Strongest signal: the payload reached a JS dialog carrying our token, so it
    # ran as script in the page's own origin. Nothing a static response can fake.
    for dialog in _items(observations.get("dialogs")):
        if canary in f"{dialog.get('message', '')}{dialog.get('default_value', '')}":
            return ValidationResult(
                "proved",
                "browser-dialog",
                f"script executed: {dialog.get('type', 'dialog')}() fired with the canary",
                _render_evidence(observations),
            )

    # Weaker but still execution: the canary came back through console.log, which
    # a static document cannot produce either. Kept separate so a reader can tell
    # which channel proved it.
    for message in _items(observations.get("console")):
        if canary in str(message.get("text", "")):
            return ValidationResult(
                "proved",
                "browser-console",
                "script executed: the canary was written to the JS console",
                _render_evidence(observations),
            )

    if observations.get("canary_in_dom"):
        return ValidationResult(
            "reflected",
            None,
            "the canary is reflected in the page but never executed — "
            "reflection alone is not a vulnerability",
            _render_evidence(observations),
        )

    return ValidationResult(
        "not_reproduced",
        None,
        "the canary did not appear in the page or execute",
        _render_evidence(observations),
    )


def _items(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, dict)]


def _render_evidence(observations: dict) -> str:
    """A short, human-readable record of the attempt, stored on the finding.

    Written for someone reading the report months later who needs to decide
    whether to believe it — the URL, what the browser did, and what it saw.
    """
    lines = [f"URL: {observations.get('url', '?')}"]
    final = observations.get("final_url")
    if final and final != observations.get("url"):
        lines.append(f"Redirected to: {final}")
    if observations.get("status") is not None:
        lines.append(f"HTTP status: {observations['status']}")
    if observations.get("title"):
        lines.append(f"Title: {observations['title']}")
    for dialog in _items(observations.get("dialogs")):
        lines.append(f"Dialog {dialog.get('type', '?')}(): {str(dialog.get('message', ''))[:200]}")
    for message in _items(observations.get("console"))[:10]:
        lines.append(f"Console [{message.get('type', 'log')}]: {str(message.get('text', ''))[:200]}")
    for err in _items(observations.get("page_errors"))[:5]:
        lines.append(f"Page error: {str(err.get('text', ''))[:200]}")
    if observations.get("error"):
        lines.append(f"Load error: {observations['error']}")
    return "\n".join(lines)[:4000]
