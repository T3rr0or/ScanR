"""OpenAI-compatible adapter — serves ChatGPT (OpenAI), DeepSeek, and any
OpenAI-compatible endpoint (self-hosted vLLM/Ollama). DeepSeek differs only by
``base_url`` and model name, so one adapter covers all of them.

The ``openai`` SDK is an optional dependency (the ``ai`` extra). It is imported
lazily so the base package and tests work without it installed.
"""
from __future__ import annotations

from .base import Completion, LLMProvider, Msg, StopReason, ToolCall, ToolDef, Usage


class OpenAICompatProvider(LLMProvider):
    def __init__(self, *, name: str, model: str, api_key: str, base_url: str | None = None):
        if not api_key:
            raise ValueError(f"{name}: API key is required")
        self.name = name
        self.model = model
        self._api_key = api_key
        self._base_url = base_url

    def _client(self):
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "The 'openai' package is required for OpenAI/DeepSeek providers. "
                "Install it with: pip install 'scanr[ai]'"
            ) from exc
        kwargs: dict = {"api_key": self._api_key}
        if self._base_url:
            kwargs["base_url"] = self._base_url
        return AsyncOpenAI(**kwargs)

    @staticmethod
    def _to_wire(system: str, messages: list[Msg]) -> list[dict]:
        wire: list[dict] = [{"role": "system", "content": system}]
        for m in messages:
            if m.role == "tool":
                wire.append({
                    "role": "tool",
                    "tool_call_id": m.tool_call_id or "",
                    "content": m.content,
                })
            elif m.role == "assistant" and m.tool_calls:
                wire.append({
                    "role": "assistant",
                    "content": m.content or None,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.name, "arguments": _dumps(tc.arguments)},
                        }
                        for tc in m.tool_calls
                    ],
                })
            else:
                wire.append({"role": m.role, "content": m.content})
        return wire

    @staticmethod
    def _tools_to_wire(tools: list[ToolDef] | None) -> list[dict] | None:
        if not tools:
            return None
        return [
            {
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
            }
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
            "messages": self._to_wire(system, messages),
            "max_tokens": max_tokens,
        }
        wire_tools = self._tools_to_wire(tools)
        if wire_tools:
            kwargs["tools"] = wire_tools

        resp = await client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        msg = choice.message

        tool_calls: list[ToolCall] = []
        for tc in (getattr(msg, "tool_calls", None) or []):
            tool_calls.append(ToolCall(
                id=tc.id,
                name=tc.function.name,
                arguments=_loads(tc.function.arguments),
            ))

        usage = Usage()
        if resp.usage:
            usage = Usage(
                input_tokens=resp.usage.prompt_tokens or 0,
                output_tokens=resp.usage.completion_tokens or 0,
                cached_input_tokens=_cached_tokens(resp.usage),
            )

        stop: StopReason = "tool_use" if tool_calls else _map_finish(choice.finish_reason)
        return Completion(text=msg.content or "", tool_calls=tool_calls, usage=usage, stop_reason=stop)


def _map_finish(reason: str | None) -> StopReason:
    if reason == "length":
        return "length"
    if reason in ("tool_calls", "function_call"):
        return "tool_use"
    return "end"


def _cached_tokens(usage) -> int:
    details = getattr(usage, "prompt_tokens_details", None)
    if details is not None:
        return getattr(details, "cached_tokens", 0) or 0
    return 0


def _dumps(obj: dict) -> str:
    import json
    return json.dumps(obj)


def _loads(raw: str) -> dict:
    import json
    try:
        val = json.loads(raw or "{}")
        return val if isinstance(val, dict) else {"_": val}
    except (ValueError, TypeError):
        return {}
