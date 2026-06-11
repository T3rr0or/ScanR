import pytest

from scanr.ai.agent.context import AgentContext
from scanr.ai.agent.loop import run_agent
from scanr.ai.agent.policy import AgentPolicy, AutonomyMode, Budget
from scanr.ai.agent.tools import Tool, ToolRegistry, read_only_tools
from scanr.ai.llm.base import Completion, LLMProvider, ToolCall, ToolDef, Usage


class FakeContext(AgentContext):
    def __init__(self, policy: AgentPolicy, *, approve: bool = False, budget: Budget | None = None):
        self.scan_id = "scan-1"
        self.policy = policy
        self.budget = budget or Budget()
        self.denylist = {"postgres"}
        self._approve = approve
        self.logs: list[str] = []
        self.approvals: list[tuple[str, dict]] = []
        self._hosts = [{"ip": "192.0.2.10", "ports": [{"number": 443}]}]
        self._findings = [
            {"id": "f1", "severity": "high", "title": "TLS issue", "host_ip": "192.0.2.10"},
            {"id": "f2", "severity": "low", "title": "Banner", "host_ip": "192.0.2.10"},
        ]

    async def list_hosts(self):
        return self._hosts

    async def list_findings(self, severity=None):
        return [f for f in self._findings if severity is None or f["severity"] == severity]

    async def get_finding(self, finding_id):
        return next((f for f in self._findings if f["id"] == finding_id), None)

    async def log(self, message):
        self.logs.append(message)

    async def request_approval(self, tool, args, reason):
        self.approvals.append((tool, args))
        return self._approve


class ScriptedProvider(LLMProvider):
    """Returns a pre-scripted sequence of completions, one per call."""

    def __init__(self, script: list[Completion]):
        self.name = "fake"
        self.model = "fake-1"
        self._script = script
        self.calls = 0

    async def complete(self, *, system, messages, tools=None, max_tokens=2048):
        c = self._script[min(self.calls, len(self._script) - 1)]
        self.calls += 1
        return c


def _reg_with(extra: Tool) -> ToolRegistry:
    return ToolRegistry(read_only_tools() + [extra])


# ── policy / budget ─────────────────────────────────────────────────────────

def test_policy_capability_gating():
    p = AgentPolicy(mode=AutonomyMode.autonomous, aggressive=False)
    assert p.allows_capability(None) is True
    assert p.allows_capability("allow_privilege_escalation") is False  # not aggressive
    p2 = AgentPolicy(aggressive=True, allow_privilege_escalation=True)
    assert p2.allows_capability("allow_privilege_escalation") is True
    p3 = AgentPolicy(aggressive=True, allow_privilege_escalation=False)
    assert p3.allows_capability("allow_privilege_escalation") is False  # capability off


def test_budget_exhaustion():
    b = Budget(max_tokens=100, max_iterations=3)
    assert b.exhausted()[0] is False
    b.add(Usage(input_tokens=80, output_tokens=30))
    assert b.exhausted()[0] is True and "token" in b.exhausted()[1]
    b2 = Budget(max_tokens=10_000, max_iterations=2)
    b2.iterations = 2
    assert b2.exhausted()[0] is True and "iteration" in b2.exhausted()[1]


# ── tool dispatch / gating ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_readonly_dispatch_returns_data():
    ctx = FakeContext(AgentPolicy())
    reg = ToolRegistry(read_only_tools())
    out = await reg.dispatch(ctx, "list_findings", {"severity": "high"})
    assert "TLS issue" in out and "Banner" not in out


@pytest.mark.asyncio
async def test_unknown_tool():
    ctx = FakeContext(AgentPolicy())
    reg = ToolRegistry(read_only_tools())
    assert (await reg.dispatch(ctx, "nope", {})).startswith("ERROR: unknown tool")


@pytest.mark.asyncio
async def test_scope_denied_for_forbidden_target():
    probe = Tool(
        ToolDef(name="probe", description="x", parameters={"type": "object", "properties": {"url": {"type": "string"}}}),
        handler=_ok_handler,
        target_args=("url",),
    )
    ctx = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous))
    reg = _reg_with(probe)
    # loopback, metadata, and the denylisted infra host are all blocked
    for tgt in ("http://127.0.0.1/", "http://169.254.169.254/", "postgres:5432"):
        out = await reg.dispatch(ctx, "probe", {"url": tgt})
        assert out.startswith("DENIED")
    # a routable target is allowed through to the handler
    assert await reg.dispatch(ctx, "probe", {"url": "http://192.0.2.10/"}) == "OK"


@pytest.mark.asyncio
async def test_capability_denied_without_optin():
    privesc = Tool(
        ToolDef(name="privesc", description="x", parameters={"type": "object", "properties": {}}),
        handler=_ok_handler,
        intrusive=True,
        required_capability="allow_privilege_escalation",
    )
    # aggressive on but capability off -> denied
    ctx = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous, aggressive=True))
    out = await _reg_with(privesc).dispatch(ctx, "privesc", {})
    assert out.startswith("DENIED") and "allow_privilege_escalation" in out


@pytest.mark.asyncio
async def test_guided_intrusive_requires_approval():
    tool = Tool(
        ToolDef(name="act", description="x", parameters={"type": "object", "properties": {}}),
        handler=_ok_handler,
        intrusive=True,
    )
    # guided + denied approval -> not executed
    ctx = FakeContext(AgentPolicy(mode=AutonomyMode.guided), approve=False)
    assert (await _reg_with(tool).dispatch(ctx, "act", {})).startswith("DENIED")
    assert ctx.approvals == [("act", {})]
    # guided + approved -> executed
    ctx2 = FakeContext(AgentPolicy(mode=AutonomyMode.guided), approve=True)
    assert await _reg_with(tool).dispatch(ctx2, "act", {}) == "OK"
    # autonomous -> no approval asked, executed
    ctx3 = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous))
    assert await _reg_with(tool).dispatch(ctx3, "act", {}) == "OK"
    assert ctx3.approvals == []


# ── loop ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_loop_runs_tools_then_finishes():
    script = [
        Completion(
            text="investigating",
            tool_calls=[ToolCall(id="t1", name="list_findings", arguments={"severity": "high"})],
            usage=Usage(input_tokens=10, output_tokens=5),
            stop_reason="tool_use",
        ),
        Completion(text="## Conclusion\nOne high finding.", usage=Usage(input_tokens=8, output_tokens=12)),
    ]
    ctx = FakeContext(AgentPolicy(mode=AutonomyMode.guided))
    run = await run_agent(ScriptedProvider(script), ctx, ToolRegistry(read_only_tools()), objective="assess")
    assert run.stop_reason == "end"
    assert run.final_text.startswith("## Conclusion")
    assert [a.tool for a in run.actions] == ["list_findings"]
    assert "TLS issue" in run.actions[0].result
    assert run.usage.input_tokens == 18


@pytest.mark.asyncio
async def test_loop_stops_on_iteration_budget():
    # model always asks for a tool -> loop must stop at the iteration ceiling
    forever = Completion(
        text="",
        tool_calls=[ToolCall(id="t", name="list_hosts", arguments={})],
        usage=Usage(input_tokens=1, output_tokens=1),
        stop_reason="tool_use",
    )
    ctx = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous), budget=Budget(max_iterations=3, max_tokens=10_000))
    run = await run_agent(ScriptedProvider([forever]), ctx, ToolRegistry(read_only_tools()), objective="loop")
    assert run.stop_reason == "max_iterations"
    assert run.iterations == 3


async def _ok_handler(ctx, args) -> str:
    return "OK"
