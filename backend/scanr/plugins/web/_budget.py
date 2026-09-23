"""A wall-clock budget for plugins whose cost grows with the target.

Payload-driven web checks multiply out: paths x parameters x payloads, each with
its own request timeout. On a slow host that product can exceed the plugin's own
declared timeout, and the engine then cancels the check mid-iteration. The run
is recorded as a timeout rather than lost silently, but the host is left with an
incomplete check and no partial result.

A budget makes the plugin decide when to stop. It bounds each port probe,
retains earlier findings, and reports honestly that it stopped early --
which is strictly better than being cancelled with nothing to show.
"""
from __future__ import annotations

import time


class Budget:
    """Wall-clock allowance for one plugin run against one host."""

    __slots__ = ("_deadline", "_seconds", "expired_early")

    def __init__(self, seconds: float):
        self._seconds = seconds
        self._deadline = time.monotonic() + seconds
        self.expired_early = False

    @property
    def remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())

    def spent(self) -> bool:
        """True once the allowance is gone; latches `expired_early` for the caller."""
        if self.remaining <= 0:
            self.expired_early = True
            return True
        return False

    def clamp(self, timeout: float) -> float:
        """Never wait longer than the budget has left, and never wait zero."""
        return max(0.5, min(timeout, self.remaining))

    def note(self) -> str:
        """A line for the finding/log when the check stopped early."""
        return (
            f"Check could not finish within its {self._seconds:.0f}s budget; "
            "coverage of this host is partial."
        )
