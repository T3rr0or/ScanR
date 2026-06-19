"""Guided/autonomous agent loop (design: docs/ai-pentest-design.md).

Provider-agnostic loop that drives ScanR's capabilities via a gated tool
registry, with in-code scope/capability enforcement, approval gates, and a
budget ceiling. Not yet wired into a live scan path.
"""

from .loop import AgentAction, AgentRun, run_agent
from .policy import AgentPolicy, AutonomyMode, Budget
from .tools import Tool, ToolRegistry, read_only_tools

__all__ = [
    "run_agent",
    "AgentRun",
    "AgentAction",
    "AgentPolicy",
    "AutonomyMode",
    "Budget",
    "Tool",
    "ToolRegistry",
    "read_only_tools",
]
