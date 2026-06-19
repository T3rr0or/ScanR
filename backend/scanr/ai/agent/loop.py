"""The provider-agnostic guided agent loop.

A manual loop (not an SDK auto-runner) so every tool call passes through the
gated dispatch, is logged for audit, and counts against the budget. The loop
stops on: the model finishing (no tool calls), the budget/iteration ceiling, or
cancellation by the caller.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

from scanr.ai.agent.context import AgentContext
from scanr.ai.agent.prompts import build_system_prompt
from scanr.ai.agent.tools import ToolRegistry
from scanr.ai.llm.base import LLMProvider, Msg, Usage


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
) -> AgentRun:
    """Drive the agent loop. ``on_action`` (if given) is awaited after each tool
    action so callers can persist the transcript live (e.g. for the UI)."""
    system = build_system_prompt(ctx.policy, scan_summary)
    messages: list[Msg] = [Msg(role="user", content=objective)]
    tool_defs = registry.definitions()
    run = AgentRun()

    while True:
        done, why = ctx.budget.exhausted()
        if done:
            run.stop_reason = "budget" if "token" in why else "max_iterations"
            await ctx.log(f"agent stopping: {why}")
            break

        ctx.budget.iterations += 1
        run.iterations += 1

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
        messages.append(
            Msg(role="assistant", content=completion.text, tool_calls=completion.tool_calls)
        )
        if completion.text:
            await ctx.log(completion.text)

        if not completion.tool_calls:
            run.final_text = completion.text
            run.stop_reason = "end"
            break

        for call in completion.tool_calls:
            await ctx.log(f"→ {call.name}({_short_args(call.arguments)})")
            result = await registry.dispatch(ctx, call.name, call.arguments)
            action = AgentAction(tool=call.name, arguments=call.arguments, result=result)
            run.actions.append(action)
            if on_action is not None:
                await on_action(action)
            messages.append(Msg(role="tool", content=result, tool_call_id=call.id, name=call.name))

    return run


def _short_args(args: dict) -> str:
    s = ", ".join(f"{k}={v!r}" for k, v in args.items())
    return s[:120]
