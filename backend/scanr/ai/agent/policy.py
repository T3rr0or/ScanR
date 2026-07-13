"""Autonomy policy and budget — the in-code guardrails for the agent loop.

The model can *request* actions; the policy decides what is actually allowed,
and the budget caps total spend. Neither can be overridden by the model (or by
prompt-injected tool output), because both are enforced here in Python.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

from scanr.ai.llm.base import Usage


class AutonomyMode(str, Enum):
    off = "off"            # no agent
    assist = "assist"      # read-only single-shot features (no agent loop)
    guided = "guided"      # agent loop; intrusive actions require approval
    autonomous = "autonomous"  # agent loop; no per-step approval (within limits)


@dataclass
class AgentPolicy:
    """What the agent is permitted to do. Aggressive capabilities each require
    their own explicit opt-in *and* an aggressive-capable mode — the mode alone
    never unlocks them."""
    mode: AutonomyMode = AutonomyMode.guided
    aggressive: bool = False
    allow_privilege_escalation: bool = False
    allow_exploitation: bool = False
    # Run arbitrary shell commands in the isolated sandbox (highest-risk capability).
    allow_command_exec: bool = False

    @property
    def runs_agent(self) -> bool:
        return self.mode in (AutonomyMode.guided, AutonomyMode.autonomous)

    @property
    def requires_approval_for_intrusive(self) -> bool:
        # guided pauses for operator approval before any intrusive action;
        # autonomous proceeds (still within scope + capability gating).
        return self.mode == AutonomyMode.guided

    def allows_capability(self, capability: str | None) -> bool:
        """Whether an aggressive capability is unlocked. None = no capability
        required (a non-aggressive action)."""
        if capability is None:
            return True
        if not self.aggressive:
            return False
        return bool(getattr(self, capability, False))


@dataclass
class Budget:
    """Hard ceiling on an agent run. Checked between iterations; when exhausted
    the loop stops and reports.

    Also enforces a per-minute input-token rate limit via a rolling window.
    When the limit would be exceeded, the loop sleeps until tokens expire."""
    max_tokens: int = 200_000
    max_iterations: int = 12
    used: Usage | None = None
    iterations: int = 0
    # Per-minute input token rate cap. 0 = no limit.
    max_input_tokens_per_minute: int = 0
    # Rolling window: list of (timestamp, input_tokens) tuples
    _window: list[tuple[float, int]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if self.used is None:
            self.used = Usage()

    def add(self, usage: Usage) -> None:
        assert self.used is not None
        self.used = self.used + usage
        # Track input tokens for rate limiting
        if self.max_input_tokens_per_minute > 0:
            now = time.monotonic()
            self._window.append((now, usage.input_tokens))

    def check_rate(self) -> float:
        """Return seconds to wait before the next call fits under the rate limit.
        0 = go ahead. Only enforced when max_input_tokens_per_minute > 0.

        Waits the *minimal* time for the trailing-60s input total to drop back
        under the cap — i.e. until exactly enough of the oldest entries expire —
        instead of a blunt "until the oldest entry expires" (which under-waits
        with many small calls) or a flat 60s. An empty window is always allowed,
        so the run keeps making forward progress even if a single call's input
        alone exceeds the cap."""
        cap = self.max_input_tokens_per_minute
        if cap <= 0:
            return 0.0
        now = time.monotonic()
        cutoff = now - 60.0
        # Prune expired entries (oldest first stays ordered by timestamp).
        self._window = [(ts, tk) for ts, tk in self._window if ts > cutoff]
        if not self._window:
            return 0.0  # nothing in the window — always allow at least one call
        total = sum(tk for _, tk in self._window)
        if total < cap:
            return 0.0
        # Over the cap: find how many of the oldest entries must expire for the
        # remaining total to fall below the cap, and wait until that entry ages
        # out of the 60s window.
        must_free = total - cap + 1
        freed = 0
        for ts, tk in self._window:
            freed += tk
            if freed >= must_free:
                return max(ts + 60.0 - now, 1.0)
        # Unreachable (freeing the whole window frees `total` >= must_free), but
        # be safe: wait for the window to fully clear.
        return max(self._window[-1][0] + 60.0 - now, 1.0)

    @property
    def total_tokens(self) -> int:
        assert self.used is not None
        return self.used.input_tokens + self.used.output_tokens

    def exhausted(self) -> tuple[bool, str]:
        # 0 (or falsy) means no ceiling — the run only stops on completion or an
        # operator Stop.
        if self.max_iterations and self.iterations >= self.max_iterations:
            return True, f"reached max iterations ({self.max_iterations})"
        if self.max_tokens and self.total_tokens >= self.max_tokens:
            return True, f"reached token budget ({self.max_tokens})"
        return False, ""
