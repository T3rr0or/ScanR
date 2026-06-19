"""LLM provider abstraction (provider-agnostic types + adapters)."""

from .base import Completion, LLMProvider, Msg, ToolCall, ToolDef, Usage
from .factory import AIProviderError, build_provider

__all__ = [
    "Completion",
    "LLMProvider",
    "Msg",
    "ToolCall",
    "ToolDef",
    "Usage",
    "AIProviderError",
    "build_provider",
]
