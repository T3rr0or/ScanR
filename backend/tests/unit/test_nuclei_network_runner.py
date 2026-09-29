"""Nuclei network/javascript template runner."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from scanr.core.engine import _filter_plugins_by_capabilities
from scanr.core.plugin_base import PluginImpact, Severity
from scanr.db.init_db import seed_templates
from scanr.models.scan_template import ScanTemplate
from scanr.plugins.nuclei import nuclei_network_runner as nr


class _Ctx:
    def __init__(self):
        self.messages = []
        self.log = SimpleNamespace(info=self._noop)

    async def _noop(self, *a, **k):
        self.messages.append((a, k))
        return None

    def performance_config(self):
        return {"nuclei_rate": 40}


def _port(number, state="open", service=None):
    return SimpleNamespace(number=number, state=state, service=service, banner=None)


def _host(ports):
    return SimpleNamespace(ip="192.0.2.10", hostname=None, ports=ports)


class _Proc:
    def __init__(self, stdout: bytes):
        self._stdout = stdout

    async def communicate(self):
        return self._stdout, b""

    def kill(self):
        pass

    async def wait(self):
        return 0


def _fake_exec(stdout: bytes, captured: dict):
    async def _factory(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return _Proc(stdout)
    return _factory


@pytest.mark.asyncio
async def test_no_nuclei_binary_returns_empty(monkeypatch):
    monkeypatch.setattr(nr.shutil, "which", lambda _: None)
    findings = await nr.NucleiNetworkRunnerPlugin().check(_Ctx(), _host([_port(7001)]))
    assert findings == []


@pytest.mark.asyncio
async def test_only_non_web_open_ports_are_targeted(monkeypatch):
    monkeypatch.setattr(nr.shutil, "which", lambda _: "/usr/bin/nuclei")
    captured: dict = {}
    monkeypatch.setattr(nr.asyncio, "create_subprocess_exec", _fake_exec(b"", captured))

    host = _host([
        _port(80),      # web — skipped
        _port(443),     # web — skipped
        _port(7001),    # weblogic t3 — targeted
        _port(3306),    # mysql — targeted
        _port(22, state="closed"),  # closed — skipped
    ])
    await nr.NucleiNetworkRunnerPlugin().check(_Ctx(), host)

    targets = [captured["cmd"][i + 1] for i, a in enumerate(captured["cmd"]) if a == "-u"]
    assert targets == ["192.0.2.10:3306", "192.0.2.10:7001"]
    # OAST callbacks cannot be confirmed through the egress proxy — must be off.
    assert "-no-interactsh" in captured["cmd"]
    # Rate limit is taken from the scan's performance config.
    assert "40" in captured["cmd"]


@pytest.mark.asyncio
async def test_port_cap_prioritizes_known_services_and_reports_skips(monkeypatch):
    monkeypatch.setattr(nr.shutil, "which", lambda _: "/usr/bin/nuclei")
    captured: dict = {}
    monkeypatch.setattr(nr.asyncio, "create_subprocess_exec", _fake_exec(b"", captured))
    ctx = _Ctx()
    host = _host([_port(number) for number in range(1, 61)] + [_port(7001), _port(27017)])

    await nr.NucleiNetworkRunnerPlugin().check(ctx, host)

    targets = [captured["cmd"][i + 1] for i, arg in enumerate(captured["cmd"]) if arg == "-u"]
    assert len(targets) == nr._MAX_TARGETS
    assert "192.0.2.10:7001" in targets
    assert "192.0.2.10:27017" in targets
    assert "192.0.2.10:60" not in targets
    assert any("12 lower-priority ports were skipped" in args[0][0] for args in ctx.messages)


@pytest.mark.asyncio
async def test_stock_network_nuclei_profile_requires_aggressive_safety(db):
    await seed_templates(db)
    result = await db.execute(
        select(ScanTemplate).where(ScanTemplate.name == "Nuclei Network Vulnerability Scan")
    )
    template = result.scalar_one()
    profile = json.loads(template.profile_json)

    assert "nuclei.network_runner" in profile["plugins"]
    assert profile["enumeration"]["nuclei"] is True
    assert profile["safety_level"] == "aggressive"

    runner = SimpleNamespace(id="nuclei.network_runner", impact=PluginImpact.exploit)
    assert _filter_plugins_by_capabilities([runner], profile) == [runner]
    balanced = {**profile, "safety_level": "balanced"}
    assert _filter_plugins_by_capabilities([runner], balanced) == []


@pytest.mark.asyncio
async def test_no_open_non_web_ports_skips_subprocess(monkeypatch):
    monkeypatch.setattr(nr.shutil, "which", lambda _: "/usr/bin/nuclei")
    called = {"ran": False}

    async def _should_not_run(*a, **k):
        called["ran"] = True
        return _Proc(b"")

    monkeypatch.setattr(nr.asyncio, "create_subprocess_exec", _should_not_run)
    findings = await nr.NucleiNetworkRunnerPlugin().check(_Ctx(), _host([_port(80), _port(443)]))
    assert findings == []
    assert called["ran"] is False


@pytest.mark.asyncio
async def test_parses_weblogic_t3_finding(monkeypatch):
    monkeypatch.setattr(nr.shutil, "which", lambda _: "/usr/bin/nuclei")
    line = json.dumps({
        "template-id": "CVE-2018-2628",
        "matched-at": "192.0.2.10:7001",
        "info": {
            "name": "Oracle WebLogic Server Deserialization RCE",
            "severity": "critical",
            "description": "T3 deserialization RCE.",
            "remediation": "Apply the Oracle CPU patch.",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2018-2628"],
            "tags": ["network", "cve", "cve2018", "kev", "oracle", "weblogic"],
        },
    }).encode()
    captured: dict = {}
    monkeypatch.setattr(nr.asyncio, "create_subprocess_exec", _fake_exec(line + b"\n", captured))

    findings = await nr.NucleiNetworkRunnerPlugin().check(_Ctx(), _host([_port(7001)]))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.critical
    assert f.port_number == 7001
    assert f.cve_ids == ["CVE-2018-2628"]
    assert "WebLogic" in f.title


@pytest.mark.asyncio
async def test_malformed_json_lines_are_ignored(monkeypatch):
    monkeypatch.setattr(nr.shutil, "which", lambda _: "/usr/bin/nuclei")
    out = b"not json\n" + json.dumps({
        "template-id": "x", "matched-at": "192.0.2.10:2049",
        "info": {"name": "NFS", "severity": "low"},
    }).encode() + b"\n\n"
    captured: dict = {}
    monkeypatch.setattr(nr.asyncio, "create_subprocess_exec", _fake_exec(out, captured))

    findings = await nr.NucleiNetworkRunnerPlugin().check(_Ctx(), _host([_port(2049)]))
    assert len(findings) == 1
    assert findings[0].port_number == 2049
