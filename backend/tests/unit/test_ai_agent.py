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

    async def run_plugin(self, plugin_id, host_ip):
        self.plugin_runs = getattr(self, "plugin_runs", [])
        self.plugin_runs.append((plugin_id, host_ip))
        return {"plugin": plugin_id, "host": host_ip, "count": 1, "recorded": 1,
                "findings": [{"severity": "high", "title": "found by plugin"}]}

    async def run_port_scan(self, host_ip, ports=None):
        self.port_scans = getattr(self, "port_scans", [])
        self.port_scans.append((host_ip, ports))
        return {"host": host_ip, "open_ports": [{"number": 80, "protocol": "tcp", "service": "http"}], "added": 1}

    async def run_command(self, command):
        self.commands = getattr(self, "commands", [])
        self.commands.append(command)
        return {"exit_code": 0, "stdout": f"ran: {command}", "stderr": "", "truncated": False, "timed_out": False}

    async def create_finding(self, severity, title, description=None, evidence=None,
                             remediation=None, host_ip=None, port_number=None, cvss_score=None):
        self.created_findings = getattr(self, "created_findings", [])
        finding = {"id": f"f{len(self._findings) + len(self.created_findings) + 1}",
                   "severity": severity, "title": title, "host_ip": host_ip}
        self.created_findings.append(finding)
        return finding


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
async def test_scope_denied_when_target_not_in_scan_scope():
    """A routable, non-forbidden host that isn't part of the scan's scope is
    still denied — the agent can't reach arbitrary third-party hosts."""
    class OutOfScopeCtx(FakeContext):
        async def is_in_scope(self, host: str) -> bool:
            return host == "192.0.2.10"

    probe = Tool(
        ToolDef(name="probe", description="x", parameters={"type": "object", "properties": {"url": {"type": "string"}}}),
        handler=_ok_handler,
        target_args=("url",),
    )
    ctx = OutOfScopeCtx(AgentPolicy(mode=AutonomyMode.autonomous))
    reg = _reg_with(probe)
    out = await reg.dispatch(ctx, "probe", {"url": "http://198.51.100.9/"})
    assert out.startswith("DENIED") and "scope" in out.lower()
    # the in-scope host still goes through
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


@pytest.mark.asyncio
async def test_default_registry_fetch_url_scope_gated():
    from scanr.ai.agent.tools import default_registry
    reg = default_registry()
    assert "fetch_url" in reg.names()
    ctx = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous))
    # forbidden targets are denied BEFORE any network call happens
    for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://postgres:5432/"):
        out = await reg.dispatch(ctx, "fetch_url", {"url": url})
        assert out.startswith("DENIED")
    # a non-http argument is rejected by the handler's own validation
    bad = await reg.dispatch(ctx, "fetch_url", {"url": "ftp://192.0.2.10/"})
    assert bad.startswith("ERROR")


@pytest.mark.asyncio
async def test_run_plugin_intrusive_gating():
    from scanr.ai.agent.tools import default_registry
    reg = default_registry()
    assert "run_plugin" in reg.names() and "list_plugins" in reg.names()

    # guided + no approval -> denied, plugin never runs
    ctx = FakeContext(AgentPolicy(mode=AutonomyMode.guided), approve=False)
    out = await reg.dispatch(ctx, "run_plugin", {"plugin_id": "web.cors", "host_ip": "192.0.2.10"})
    assert out.startswith("DENIED")
    assert getattr(ctx, "plugin_runs", []) == []

    # autonomous -> runs, returns the plugin findings
    ctx2 = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous))
    out2 = await reg.dispatch(ctx2, "run_plugin", {"plugin_id": "web.cors", "host_ip": "192.0.2.10"})
    assert "found by plugin" in out2
    assert ctx2.plugin_runs == [("web.cors", "192.0.2.10")]

    # scope still enforced: a forbidden host is denied before the plugin runs
    ctx3 = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous))
    out3 = await reg.dispatch(ctx3, "run_plugin", {"plugin_id": "web.cors", "host_ip": "127.0.0.1"})
    assert out3.startswith("DENIED")
    assert getattr(ctx3, "plugin_runs", []) == []


@pytest.mark.asyncio
async def test_run_port_scan_intrusive_gating():
    from scanr.ai.agent.tools import default_registry
    reg = default_registry()
    assert "run_port_scan" in reg.names()

    # guided + no approval -> denied, scan never runs
    ctx = FakeContext(AgentPolicy(mode=AutonomyMode.guided), approve=False)
    out = await reg.dispatch(ctx, "run_port_scan", {"host_ip": "192.0.2.10", "ports": "80,443"})
    assert out.startswith("DENIED")
    assert getattr(ctx, "port_scans", []) == []

    # autonomous -> runs
    ctx2 = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous))
    out2 = await reg.dispatch(ctx2, "run_port_scan", {"host_ip": "192.0.2.10", "ports": "80,443"})
    assert "open_ports" in out2
    assert ctx2.port_scans == [("192.0.2.10", "80,443")]

    # scope enforced before the scan runs
    ctx3 = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous))
    out3 = await reg.dispatch(ctx3, "run_port_scan", {"host_ip": "169.254.169.254"})
    assert out3.startswith("DENIED")
    assert getattr(ctx3, "port_scans", []) == []


@pytest.mark.asyncio
async def test_run_command_only_exposed_with_capability():
    from scanr.ai.agent.tools import default_registry

    # No capability -> the tool isn't even in the registry the model sees
    reg_off = default_registry(AgentPolicy(mode=AutonomyMode.autonomous, aggressive=True))
    assert "run_command" not in reg_off.names()

    # With allow_command_exec (and aggressive) -> exposed
    pol = AgentPolicy(mode=AutonomyMode.autonomous, aggressive=True, allow_command_exec=True)
    reg_on = default_registry(pol)
    assert "run_command" in reg_on.names()


@pytest.mark.asyncio
async def test_run_command_capability_and_approval_gating():
    from scanr.ai.agent.tools import command_tools

    cmd_tool = command_tools()[0]

    # aggressive but capability off -> denied (defense in depth even if exposed)
    ctx_off = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous, aggressive=True))
    out = await _reg_with(cmd_tool).dispatch(ctx_off, "run_command", {"command": "id"})
    assert out.startswith("DENIED") and "allow_command_exec" in out

    # capability on, autonomous -> runs
    ctx_on = FakeContext(AgentPolicy(mode=AutonomyMode.autonomous, aggressive=True, allow_command_exec=True))
    out2 = await _reg_with(cmd_tool).dispatch(ctx_on, "run_command", {"command": "id"})
    assert "ran: id" in out2
    assert ctx_on.commands == ["id"]

    # guided + capability on but no approval -> denied, command not run
    ctx_guided = FakeContext(
        AgentPolicy(mode=AutonomyMode.guided, aggressive=True, allow_command_exec=True), approve=False
    )
    out3 = await _reg_with(cmd_tool).dispatch(ctx_guided, "run_command", {"command": "id"})
    assert out3.startswith("DENIED")
    assert getattr(ctx_guided, "commands", []) == []


def test_parse_ports():
    from scanr.ai.agent.db_context import _parse_ports
    assert _parse_ports("80,443") == [80, 443]
    assert _parse_ports("80,8000-8002") == [80, 8000, 8001, 8002]
    with pytest.raises(ValueError):
        _parse_ports("0-10")  # 0 invalid
    with pytest.raises(ValueError):
        _parse_ports("1-70000")  # out of range
    with pytest.raises(ValueError):
        _parse_ports("1-3000")  # >2000 ports


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
    run, _ = await run_agent(ScriptedProvider(script), ctx, ToolRegistry(read_only_tools()), objective="assess")
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
    run, _ = await run_agent(ScriptedProvider([forever]), ctx, ToolRegistry(read_only_tools()), objective="loop")
    assert run.stop_reason == "max_iterations"
    assert run.iterations == 3


@pytest.mark.asyncio
async def test_resume_does_not_reinject_objective():
    """On resume (messages given), the loop must answer the latest user turn,
    not re-append the original objective (regression for the chat-resume bug)."""
    from scanr.ai.llm.base import Msg

    prior = [
        Msg(role="user", content="ORIGINAL OBJECTIVE"),
        Msg(role="assistant", content="done first turn"),
        Msg(role="user", content="now test xss"),  # the follow-up
    ]
    ctx = FakeContext(AgentPolicy(mode=AutonomyMode.guided))
    script = [Completion(text="answering the follow-up", usage=Usage(input_tokens=1, output_tokens=1))]
    run, msgs = await run_agent(
        ScriptedProvider(script), ctx, ToolRegistry(read_only_tools()),
        objective="ORIGINAL OBJECTIVE", messages=prior,
    )
    # The original objective must NOT have been appended again as a new turn.
    assert sum(1 for m in msgs if m.role == "user" and m.content == "ORIGINAL OBJECTIVE") == 1
    # The follow-up must remain the last user turn the model saw.
    user_turns = [m for m in msgs if m.role == "user"]
    assert user_turns[-1].content == "now test xss"


@pytest.mark.asyncio
async def test_loop_stops_when_should_stop():
    """The cooperative stop signal ends the run with stop_reason='stopped'."""
    class StoppingCtx(FakeContext):
        async def should_stop(self):
            return True

    forever = Completion(
        text="",
        tool_calls=[ToolCall(id="t", name="list_hosts", arguments={})],
        usage=Usage(input_tokens=1, output_tokens=1),
        stop_reason="tool_use",
    )
    ctx = StoppingCtx(AgentPolicy(mode=AutonomyMode.autonomous))
    run, _ = await run_agent(ScriptedProvider([forever]), ctx, ToolRegistry(read_only_tools()), objective="loop")
    assert run.stop_reason == "stopped"
    assert run.iterations == 0  # stopped before the first model call


def test_budget_zero_means_unlimited():
    # 0 disables a ceiling so a run only ends on completion or operator Stop.
    b = Budget(max_iterations=0, max_tokens=0)
    b.iterations = 10_000
    b.add(Usage(input_tokens=10_000_000, output_tokens=10_000_000))
    assert b.exhausted() == (False, "")
    # A finite ceiling still trips even when the other is unlimited.
    b2 = Budget(max_iterations=2, max_tokens=0)
    b2.iterations = 2
    assert b2.exhausted()[0] is True


async def _ok_handler(ctx, args) -> str:
    return "OK"
