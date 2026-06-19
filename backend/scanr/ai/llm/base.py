"""Provider-agnostic LLM types and the LLMProvider interface.

Everything above this layer (the agent loop, assist features) speaks only these
normalized types. Adapters in ``openai_compat.py`` and ``anthropic.py`` translate
to and from each provider's wire format. Tool JSON Schema is shared across
providers; only the envelope differs, and the adapters hide that.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

Role = Literal["system", "user", "assistant", "tool"]


@dataclass
class ToolCall:
    """A tool invocation requested by the model."""
    id: str
    name: str
    arguments: dict


@dataclass
class ToolDef:
    """A tool the model may call. ``parameters`` is a JSON Schema object."""
    name: str
    description: str
    parameters: dict


@dataclass
class Msg:
    """One normalized conversation message.

    - ``role="tool"`` carries a tool result: set ``tool_call_id`` (and
      optionally ``name``) and put the result text in ``content``.
    - ``role="assistant"`` may carry ``tool_calls`` the model requested.
    """
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cached_input_tokens=self.cached_input_tokens + other.cached_input_tokens,
        )


StopReason = Literal["end", "tool_use", "length", "error"]


@dataclass
class Completion:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    stop_reason: StopReason = "end"


class LLMProvider(ABC):
    """Common interface implemented by every provider adapter."""

    #: short provider id, e.g. "anthropic", "openai", "deepseek"
    name: str
    #: concrete model id passed to the provider
    model: str

    @abstractmethod
    async def complete(
        self,
        *,
        system: str,
        messages: list[Msg],
        tools: list[ToolDef] | None = None,
        max_tokens: int = 2048,
    ) -> Completion:
        """Run one completion and return the normalized result."""
        raise NotImplementedError
