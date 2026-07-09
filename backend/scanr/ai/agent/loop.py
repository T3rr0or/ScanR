"""The provider-agnostic guided agent loop.

A manual loop (not an SDK auto-runner) so every tool call passes through the
gated dispatch, is logged for audit, and counts against the budget. The loop
stops on: the model finishing (no tool calls), the budget/iteration ceiling, or
cancellation by the caller.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from scanr.ai.agent.context import AgentContext
from scanr.ai.agent.prompts import build_system_prompt
from scanr.ai.agent.tools import ToolRegistry
from scanr.ai.llm.base import LLMProvider, Msg, Usage

logger = logging.getLogger(__name__)


@dataclass
class AgentAction:
    tool: str
    arguments: dict
    result: str


@dataclass
class AgentRun:
    final_text: str = ""
    actions: list[AgentAction] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    iterations: int = 0
    stop_reason: str = "end"  # end | budget | max_iterations | error


async def run_agent(
    provider: LLMProvider,
    ctx: AgentContext,
    registry: ToolRegistry,
    *,
    objective: str,
    scan_summary: str = "",
    max_tokens_per_call: int = 4096,
    on_action: "Callable[[AgentAction], Awaitable[None]] | None" = None,
    on_step: "Callable[[list[Msg]], Awaitable[None]] | None" = None,
    messages: list[Msg] | None = None,
    usage: Usage | None = None,
    iterations: int = 0,
) -> tuple[AgentRun, list[Msg]]:
    """Drive the agent loop. Returns the run result AND the complete message
    history (for serialization as conversation).

    Pass ``messages``, ``usage``, and ``iterations`` to resume an existing
    conversation — on resume the latest user turn is already the last message,
    so the objective is NOT re-appended. ``on_step`` (if given) is awaited with
    the running message list after each turn so callers can stream the
    conversation to the UI live."""
    system = build_system_prompt(ctx.policy, scan_summary)
    if messages:
        # Resuming: the new user message is already the last entry — don't
        # re-inject the original objective (that would answer the wrong prompt
        # and produce two consecutive user turns, which some providers reject).
        pass
    else:
        messages = [Msg(role="user", content=objective)]
    tool_defs = registry.definitions()
    run = AgentRun(usage=usage or Usage(), iterations=iterations)

    while True:
        if await ctx.should_stop():
            run.stop_reason = "stopped"
            await ctx.log("agent stopped by user")
            break

        done, why = ctx.budget.exhausted()
        if done:
            run.stop_reason = "budget" if "token" in why else "max_iterations"
            await ctx.log(f"agent stopping: {why}")
            break

        ctx.budget.iterations += 1
        run.iterations += 1

        # Rate-limit: pause if input tokens/min cap would be exceeded.
        # Uses a rolling 60s window — sleeps until oldest tokens expire.
        wait = ctx.budget.check_rate()
        if wait > 0:
            logger.info("rate limit: waiting %.1fs before next API call", wait)
            await ctx.log(f"⏳ rate limit — waiting {wait:.0f}s before next LLM call")
            await asyncio.sleep(wait)

        completion = await provider.complete(
            system=system,
            messages=messages,
            tools=tool_defs,
            max_tokens=max_tokens_per_call,
        )
        ctx.budget.add(completion.usage)
        run.usage = run.usage + completion.usage

        # Record the assistant turn (text + any tool calls) so the model sees
        # its own prior actions on the next iteration.
        messages.append(Msg(role="assistant", content=completion.text, tool_calls=completion.tool_calls))
        if completion.text:
            await ctx.log(completion.text)

        if not completion.tool_calls:
            run.final_text = completion.text
            run.stop_reason = "end"
            if on_step is not None:
                await on_step(messages)
            break

        for call in completion.tool_calls:
            # Full, exact command line for the audit trail — every tool, including
            # the built-ins (fetch_url, run_port_scan, …), with complete arguments
            # so an auditor/customer can see precisely what was executed.
            await ctx.log(f"→ {call.name}({_full_args(call.arguments)})")
            result = await registry.dispatch(ctx, call.name, call.arguments)
            await ctx.log(f"← {call.name}: {_preview(result)}")
            action = AgentAction(tool=call.name, arguments=call.arguments, result=result)
            run.actions.append(action)
            if on_action is not None:
                await on_action(action)
            messages.append(Msg(role="tool", content=result, tool_call_id=call.id, name=call.name))

        # Stream the conversation after each completed turn so the UI updates
        # live instead of only when the whole run finishes.
        if on_step is not None:
            await on_step(messages)

    return run, messages


def _full_args(args: dict) -> str:
    """Exact JSON of the tool arguments for the audit trail (no truncation)."""
    import json

    try:
        return json.dumps(args, ensure_ascii=False, default=str)
    except Exception:  # noqa: BLE001
        return repr(args)


def _preview(result: str, limit: int = 2000) -> str:
    """A bounded preview of a tool result for the console (full result is kept
    in the run transcript)."""
    result = result or ""
    return result if len(result) <= limit else result[:limit] + f"… ({len(result)} chars)"
