"""Agent tool registry and scope/capability-gated dispatch.

Tools wrap ScanR capabilities behind validated, typed entry points — never a
raw shell. Every dispatch enforces, in code:
  1. scope — any target argument is checked against is_forbidden_target, so the
     model can never point an action at loopback / metadata / scanner infra;
  2. capability — aggressive tools run only when the policy unlocks them;
  3. approval — in guided mode intrusive tools pause for operator approval.

This first slice ships the read-only tools (over already-collected scan data),
which exercise the whole loop at near-zero risk. Active/intrusive tools slot
into the same registry later with the gating already in force.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from scanr.ai.agent.context import AgentContext
from scanr.ai.llm.base import ToolDef
from scanr.utils.ip_utils import is_forbidden_target

Handler = Callable[[AgentContext, dict], Awaitable[str]]


@dataclass
class Tool:
    definition: ToolDef
    handler: Handler
    intrusive: bool = False
    #: policy attribute that must be set (e.g. "allow_privilege_escalation"),
    #: or None for a tool that needs no aggressive capability
    required_capability: str | None = None
    #: names of arguments that are scan targets (host/ip/url) — validated
    #: against the scope denylist before the handler runs
    target_args: tuple[str, ...] = field(default_factory=tuple)


class ToolError(Exception):
    """Raised by a handler for an expected, model-actionable failure."""


# ── read-only tool handlers ────────────────────────────────────────────────

async def _list_hosts(ctx: AgentContext, args: dict) -> str:
    hosts = await ctx.list_hosts()
    return json.dumps(hosts)[:8000]


async def _list_findings(ctx: AgentContext, args: dict) -> str:
    sev = args.get("severity")
    if sev is not None and sev not in ("critical", "high", "medium", "low", "info"):
        raise ToolError(f"invalid severity {sev!r}")
    findings = await ctx.list_findings(severity=sev)
    return json.dumps(findings)[:8000]


async def _get_finding(ctx: AgentContext, args: dict) -> str:
    fid = str(args.get("finding_id", ""))
    if not fid:
        raise ToolError("finding_id is required")
    finding = await ctx.get_finding(fid)
    if finding is None:
        raise ToolError(f"finding {fid!r} not found in this scan")
    return json.dumps(finding)[:8000]



async def _create_finding(ctx: AgentContext, args: dict) -> str:
    severity = str(args.get("severity", "")).strip().lower()
    title = str(args.get("title", "")).strip()
    if not severity or not title:
        raise ToolError("severity and title are required")
    if severity not in ("critical", "high", "medium", "low", "info"):
        raise ToolError(f"invalid severity {severity!r}; must be critical/high/medium/low/info")
    desc = str(args.get("description", "")).strip() or None
    evidence = str(args.get("evidence", "")).strip() or None
    remediation = str(args.get("remediation", "")).strip() or None
    host_ip = str(args.get("host_ip", "")).strip() or None
    port = args.get("port_number")
    if port is not None:
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ToolError("port_number must be an integer")
    cvss = args.get("cvss_score")
    if cvss is not None:
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            raise ToolError("cvss_score must be a number")
    result = await ctx.create_finding(
        severity=severity,
        title=title,
        description=desc,
        evidence=evidence,
        remediation=remediation,
        host_ip=host_ip,
        port_number=port,
        cvss_score=cvss,
    )
    return json.dumps(result)

def read_only_tools() -> list[Tool]:
    return [
        Tool(
            ToolDef(
                name="list_hosts",
                description="List discovered hosts in this scan with their open ports and services.",
                parameters={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            _list_hosts,
        ),
        Tool(
            ToolDef(
                name="list_findings",
                description="List findings for this scan. Optionally filter by severity.",
                parameters={
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Only return findings of this severity.",
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            _list_findings,
        ),
        Tool(
            ToolDef(
                name="get_finding",
                description="Get one finding by id, including its full evidence.",
                parameters={
                    "type": "object",
                    "properties": {"finding_id": {"type": "string"}},
                    "required": ["finding_id"],
                    "additionalProperties": False,
                },
            ),
            _get_finding,
        ),
        Tool(
            ToolDef(
                name="create_finding",
                description="Create a new finding discovered by the agent. Use this to add findings that you discover during the engagement.",
                parameters={
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Severity of the finding.",
                        },
                        "title": {"type": "string", "description": "Short title for the finding (max 512 chars)."},
                        "description": {"type": "string", "description": "Detailed description of the finding."},
                        "evidence": {"type": "string", "description": "Evidence supporting the finding."},
                        "remediation": {"type": "string", "description": "Suggested remediation steps."},
                        "host_ip": {"type": "string", "description": "IP of the affected host."},
                        "port_number": {"type": "integer", "description": "Affected port number."},
                        "cvss_score": {"type": "number", "description": "CVSS score (0.0-10.0)."},
                    },
                    "required": ["severity", "title"],
                    "additionalProperties": False,
                },
            ),
            _create_finding,
        ),
    ]


async def _fetch_url(ctx: AgentContext, args: dict) -> str:
    url = str(args.get("url", "")).strip()
    if not url:
        raise ToolError("url is required")
    if not url.startswith(("http://", "https://")):
        raise ToolError("url must start with http:// or https://")
    method = str(args.get("method", "GET")).strip().upper()
    if method not in ("GET", "POST"):
        raise ToolError("method must be GET or POST")
    body_raw = str(args.get("body", "")).strip() or None
    content_type = str(args.get("content_type", "application/x-www-form-urlencoded")).strip()
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            if method == "POST":
                resp = await client.post(url, content=body_raw, headers={"content-type": content_type})
            else:
                resp = await client.get(url)
    except Exception as exc:  # noqa: BLE001 - report any fetch failure to the model
        raise ToolError(f"request failed: {exc}")
    interesting = {
        k: v for k, v in resp.headers.items()
        if k.lower() in ("server", "content-type", "location", "x-powered-by", "www-authenticate", "set-cookie")
    }
    body = resp.text[:4000]
    return json.dumps({
        "status": resp.status_code,
        "headers": interesting,
        "body_snippet": body,
        "truncated": len(resp.text) > 4000,
    })


def web_tools() -> list[Tool]:
    """Active but non-intrusive tools (GET requests). Scope-checked on the host."""
    return [
        Tool(
            ToolDef(
                name="fetch_url",
                description=(
                    "HTTP request to a URL on a discovered host. Returns status, key headers, "
                    "and a body snippet. Use method=POST with body and content_type to submit "
                    "forms (e.g. login, search). Use GET by default for reading pages. "
                    "Not proxy-filtered — POST goes directly from the worker. Non-intrusive."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Absolute http(s) URL"},
                        "method": {"type": "string", "enum": ["GET", "POST"], "description": "HTTP method (default GET)"},
                        "body": {"type": "string", "description": "Request body for POST (e.g. 'username=admin&password=test')"},
                        "content_type": {"type": "string", "description": "Content-Type header for POST (default: application/x-www-form-urlencoded)"},
                    },
                    "required": ["url"],
                    "additionalProperties": False,
                },
            ),
            _fetch_url,
            target_args=("url",),
        ),
    ]


async def _list_plugins(ctx: AgentContext, args: dict) -> str:
    from scanr.core import plugin_manager

    classes = plugin_manager.get_all_plugin_classes()
    out = [
        {
            "id": pid,
            "name": getattr(cls, "name", pid),
            "category": getattr(getattr(cls, "category", None), "value", str(getattr(cls, "category", ""))),
            "destructive": bool(getattr(cls, "destructive", False)),
            "requires_auth": bool(getattr(cls, "requires_auth", False)),
        }
        for pid, cls in classes.items()
    ]
    return json.dumps(out)[:12000]


async def _run_plugin(ctx: AgentContext, args: dict) -> str:
    plugin_id = str(args.get("plugin_id", "")).strip()
    host_ip = str(args.get("host_ip", "")).strip()
    if not plugin_id or not host_ip:
        raise ToolError("plugin_id and host_ip are required")
    try:
        result = await ctx.run_plugin(plugin_id, host_ip)
    except ValueError as exc:
        raise ToolError(str(exc))
    if result.get("denied"):
        return f"DENIED: {result.get('reason', 'not permitted')}"
    return json.dumps(result)[:8000]


async def _run_port_scan(ctx: AgentContext, args: dict) -> str:
    host_ip = str(args.get("host_ip", "")).strip()
    if not host_ip:
        raise ToolError("host_ip is required")
    ports = args.get("ports")
    try:
        result = await ctx.run_port_scan(host_ip, str(ports) if ports else None)
    except ValueError as exc:
        raise ToolError(str(exc))
    return json.dumps(result)[:8000]


def plugin_tools() -> list[Tool]:
    """Active tools that run ScanR plugins / scans against a host (intrusive)."""
    return [
        Tool(
            ToolDef(
                name="run_port_scan",
                description=(
                    "Nmap-scan a discovered host (optionally a port spec like '80,443' or "
                    "'1-1024'; max 2000 ports). Persists newly found ports/services. "
                    "Intrusive: approval-gated in guided mode."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "host_ip": {"type": "string"},
                        "ports": {"type": "string", "description": "Optional port spec, e.g. '80,443,8000-8010'"},
                    },
                    "required": ["host_ip"],
                    "additionalProperties": False,
                },
            ),
            _run_port_scan,
            intrusive=True,
            target_args=("host_ip",),
        ),
        Tool(
            ToolDef(
                name="list_plugins",
                description="List available ScanR plugins (id, category, whether destructive) to choose from.",
                parameters={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            _list_plugins,
        ),
        Tool(
            ToolDef(
                name="run_plugin",
                description=(
                    "Run a ScanR plugin against a discovered host to actively check it. "
                    "Intrusive: in guided mode this requires operator approval. Destructive "
                    "plugins additionally require the exploitation capability."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "plugin_id": {"type": "string"},
                        "host_ip": {"type": "string"},
                    },
                    "required": ["plugin_id", "host_ip"],
                    "additionalProperties": False,
                },
            ),
            _run_plugin,
            intrusive=True,
            target_args=("host_ip",),
        ),
    ]


async def _run_command(ctx: AgentContext, args: dict) -> str:
    command = str(args.get("command", "")).strip()
    if not command:
        raise ToolError("command is required")
    result = await ctx.run_command(command)
    if result.get("denied"):
        return f"DENIED: {result.get('reason', 'not permitted')}"
    return json.dumps(result)[:8000]


def command_tools() -> list[Tool]:
    """Arbitrary shell in the isolated sandbox — the highest-risk tool. Requires
    the allow_command_exec capability (admin + aggressive opt-in)."""
    return [
        Tool(
            ToolDef(
                name="run_command",
                description=(
                    "Run a shell command in a PERSISTENT, isolated sandbox container (Kali). "
                    "State persists across calls in this run: installs, downloaded files, the "
                    "working directory (/work), and footholds all survive between commands, so "
                    "build on previous steps instead of repeating setup. A broad toolkit is "
                    "ALREADY installed — nmap, masscan, nikto, sqlmap, gobuster, ffuf, "
                    "feroxbuster, wfuzz, whatweb, wpscan, hydra, john, smbclient, curl, git, "
                    "python3/pip — and SecLists wordlists are at /usr/share/seclists. Do NOT "
                    "waste steps reinstalling these; just run them. Only install (pip install "
                    "--user / git clone / go install) for tools not already present. Network "
                    "egress is restricted to the scan's authorized targets plus package mirrors. "
                    "Runs non-root, so raw-socket scans fall back to TCP connect."
                ),
                parameters={
                    "type": "object",
                    "properties": {"command": {"type": "string", "description": "Shell command to run"}},
                    "required": ["command"],
                    "additionalProperties": False,
                },
            ),
            _run_command,
            intrusive=True,
            required_capability="allow_command_exec",
        ),
    ]


def default_registry(policy=None) -> "ToolRegistry":
    """The tool set for a guided/autonomous run: read-only + web + plugins, and
    the sandbox shell only when the policy unlocks allow_command_exec (so the
    model isn't even shown a tool it can't use).

    list_plugins is read-only; run_plugin/run_port_scan are intrusive
    (approval-gated in guided mode; destructive plugins gated on exploitation).
    """
    tools = read_only_tools() + web_tools() + plugin_tools()
    if policy is not None and policy.allows_capability("allow_command_exec"):
        tools += command_tools()
    return ToolRegistry(tools)


class ToolRegistry:
    """Holds the tools available for a run and exposes the gated dispatch."""

    def __init__(self, tools: list[Tool]):
        self._tools = {t.definition.name: t for t in tools}

    def definitions(self) -> list[ToolDef]:
        return [t.definition for t in self._tools.values()]

    def names(self) -> list[str]:
        return list(self._tools)

    async def dispatch(self, ctx: AgentContext, name: str, args: dict) -> str:
        """Run a tool with all guardrails. Returns the tool_result text — including
        a clear denial string when a guardrail blocks it, so the model can adapt
        rather than the run erroring out."""
        tool = self._tools.get(name)
        if tool is None:
            return f"ERROR: unknown tool {name!r}"

        # 1. scope — never let a target point at forbidden infrastructure
        for arg in tool.target_args:
            value = str(args.get(arg, "")).strip()
            target = _host_of(value)
            if target and is_forbidden_target(target, ctx.denylist):
                await ctx.log(f"blocked out-of-scope target {target!r} for {name}")
                return f"DENIED: target {target!r} is out of scope (loopback / metadata / scanner infrastructure)."

        # 2. capability — aggressive tools need the matching opt-in
        if not ctx.policy.allows_capability(tool.required_capability):
            return (
                f"DENIED: {name} requires the '{tool.required_capability}' capability, "
                "which is not enabled for this scan."
            )

        # 3. approval — guided mode pauses before intrusive actions
        if tool.intrusive and ctx.policy.requires_approval_for_intrusive:
            approved = await ctx.request_approval(name, args, reason="intrusive action")
            if not approved:
                return f"DENIED: operator did not approve {name}."

        try:
            return await tool.handler(ctx, args)
        except ToolError as exc:
            return f"ERROR: {exc}"


def _host_of(value: str) -> str:
    """Extract the host from a target arg that may be a URL or host:port."""
    if not value:
        return ""
    if "://" in value:
        from urllib.parse import urlparse

        return urlparse(value).hostname or ""
    return value.split(":", 1)[0]
