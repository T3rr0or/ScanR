"""AgentContext — the agent's bounded view of the world.

The loop and tools only ever touch the world through this object: read scan
data, fetch a URL, log to the console, and ask for operator approval. The real
implementation (next slice) backs these with the DB / scan engine / WebSocket;
tests use an in-memory fake. Centralizing access here is what lets scope and
capability checks be enforced in one place.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from scanr.ai.agent.policy import AgentPolicy, Budget


class AgentContext(ABC):
    scan_id: str
    policy: AgentPolicy
    budget: Budget
    #: extra infra hostnames/IPs that may never be targeted (merged with the
    #: built-in loopback/link-local/metadata denylist by is_forbidden_target)
    denylist: set[str]

    @abstractmethod
    async def list_hosts(self) -> list[dict]:
        """Discovered hosts (ip, hostname, os, open ports/services)."""

    @abstractmethod
    async def list_findings(self, severity: str | None = None) -> list[dict]:
        """Findings for the scan, optionally filtered by severity."""

    @abstractmethod
    async def get_finding(self, finding_id: str) -> dict | None:
        """One finding including its evidence, or None if not in this scan."""

    @abstractmethod
    async def log(self, message: str) -> None:
        """Surface a line to the live scan console / audit trail."""

    @abstractmethod
    async def request_approval(self, tool: str, args: dict, reason: str) -> bool:
        """Ask the operator to approve an intrusive action. Returns True to run.

        In autonomous mode this is not called; in guided mode the real impl
        blocks on operator input via the API/WebSocket.
        """

    @abstractmethod
    async def run_plugin(self, plugin_id: str, host_ip: str) -> dict:
        """Run one ScanR plugin against a discovered host and return a result
        dict (findings, count). Destructive plugins are additionally gated on
        the exploitation capability by the implementation. Raises on bad input."""
