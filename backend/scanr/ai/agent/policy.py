"""Autonomy policy and budget — the in-code guardrails for the agent loop.

The model can *request* actions; the policy decides what is actually allowed,
and the budget caps total spend. Neither can be overridden by the model (or by
prompt-injected tool output), because both are enforced here in Python.
"""
from __future__ import annotations

from dataclasses import dataclass
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
    the loop stops and reports."""
    max_tokens: int = 200_000
    max_iterations: int = 12
    used: Usage | None = None
    iterations: int = 0

    def __post_init__(self) -> None:
        if self.used is None:
            self.used = Usage()

    def add(self, usage: Usage) -> None:
        assert self.used is not None
        self.used = self.used + usage

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
