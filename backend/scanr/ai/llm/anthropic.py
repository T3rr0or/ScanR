"""Anthropic (Claude) adapter via the Messages API.

The ``anthropic`` SDK is an optional dependency (the ``ai`` extra), imported
lazily. The system prompt is a top-level parameter (not a message), and tool
results are carried as ``tool_result`` content blocks inside a user turn —
both handled here so callers only ever deal with the normalized types.
"""
from __future__ import annotations

import asyncio
import logging

from .base import Completion, LLMProvider, Msg, StopReason, ToolCall, ToolDef, Usage

logger = logging.getLogger(__name__)


class AnthropicProvider(LLMProvider):
    def __init__(self, *, model: str, api_key: str):
        if not api_key:
            raise ValueError("anthropic: API key is required")
        self.name = "anthropic"
        self.model = model
        self._api_key = api_key

    def _client(self):
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "The 'anthropic' package is required for the Anthropic provider. "
                "Install it with: pip install 'scanr[ai]'"
            ) from exc
        return AsyncAnthropic(api_key=self._api_key)

    @staticmethod
    def _to_wire(messages: list[Msg]) -> list[dict]:
        wire: list[dict] = []
        for m in messages:
            if m.role == "tool":
                wire.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id or "",
                        "content": m.content,
                    }],
                })
            elif m.role == "assistant" and m.tool_calls:
                blocks: list[dict] = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments,
                    })
                wire.append({"role": "assistant", "content": blocks})
            else:
                # Anthropic accepts only "user"/"assistant" roles in messages
                role = "assistant" if m.role == "assistant" else "user"
                wire.append({"role": role, "content": m.content})
        return wire

    @staticmethod
    def _tools_to_wire(tools: list[ToolDef] | None) -> list[dict] | None:
        if not tools:
            return None
        return [
            {"name": t.name, "description": t.description, "input_schema": t.parameters}
            for t in tools
        ]

    async def complete(
        self,
        *,
        system: str,
        messages: list[Msg],
        tools: list[ToolDef] | None = None,
        max_tokens: int = 2048,
    ) -> Completion:
        client = self._client()
        kwargs: dict = {
            "model": self.model,
            "system": system,
            "messages": self._to_wire(messages),
            "max_tokens": max_tokens,
        }
        wire_tools = self._tools_to_wire(tools)
        if wire_tools:
            kwargs["tools"] = wire_tools

        # Retry on rate limits with exponential backoff (up to 3 attempts)
        for attempt in range(3):
            try:
                resp = await client.messages.create(**kwargs)
                break
            except Exception as exc:
                is_rate_limit = (
                    hasattr(exc, "status_code") and getattr(exc, "status_code", 0) == 429
                ) or "rate_limit" in str(exc).lower()
                if is_rate_limit and attempt < 2:
                    delay = 2 ** attempt * 15  # 15s, 30s
                    logger.warning("anthropic rate limit hit, retrying in %ds (attempt %d/3)", delay, attempt + 2)
                    await asyncio.sleep(delay)
                    # Switch to a cheaper model hint for the retry
                    continue
                raise

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in resp.content:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(block.text)
            elif btype == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, arguments=dict(block.input)))

        usage = Usage(
            input_tokens=getattr(resp.usage, "input_tokens", 0) or 0,
            output_tokens=getattr(resp.usage, "output_tokens", 0) or 0,
            cached_input_tokens=getattr(resp.usage, "cache_read_input_tokens", 0) or 0,
        )
        stop: StopReason = "tool_use" if tool_calls else _map_stop(resp.stop_reason)
        return Completion(text="".join(text_parts), tool_calls=tool_calls, usage=usage, stop_reason=stop)


def _map_stop(reason: str | None) -> StopReason:
    if reason == "max_tokens":
        return "length"
    if reason == "tool_use":
        return "tool_use"
    return "end"
