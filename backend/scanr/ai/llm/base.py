"""Provider-agnostic LLM types and the LLMProvider interface.

Everything above this layer (the agent loop, assist features) speaks only these
normalized types. Adapters in ``openai_compat.py`` and ``anthropic.py`` translate
to and from each provider's wire format. Tool JSON Schema is shared across
providers; only the envelope differs, and the adapters hide that.
"""
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Literal, TypeVar

Role = Literal["system", "user", "assistant", "tool"]

logger = logging.getLogger(__name__)

T = TypeVar("T")


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


async def retry_on_rate_limit(call: Callable[[], Awaitable[T]], *, provider: str, attempts: int = 3) -> T:
    """Run ``call``, retrying with exponential backoff (15s, 30s, ...) if it
    raises an exception carrying ``status_code == 429``. Re-raises on the
    final attempt or on any non-429 error."""
    for attempt in range(attempts):
        try:
            return await call()
        except Exception as exc:
            is_rate_limit = getattr(exc, "status_code", None) == 429
            if is_rate_limit and attempt < attempts - 1:
                delay = 2 ** attempt * 15
                logger.warning(
                    "%s rate limit hit, retrying in %ds (attempt %d/%d)",
                    provider, delay, attempt + 2, attempts,
                )
                await asyncio.sleep(delay)
                continue
            raise
    raise AssertionError("unreachable")  # pragma: no cover
