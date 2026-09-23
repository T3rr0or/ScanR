"""Budget exhaustion must survive the plugin -> engine -> report boundary."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from scanr.core.engine import ScanEngine
from scanr.core.plugin_base import BudgetedFindings, FindingData, Severity
from scanr.plugins.web import command_injection, crlf_injection, nosql_injection
from scanr.reporting.coverage import build_coverage


@pytest.mark.parametrize('module,cls', [
    (command_injection, command_injection.CommandInjectionPlugin),
    (crlf_injection, crlf_injection.CrlfInjectionPlugin),
    (nosql_injection, nosql_injection.NoSqlInjectionPlugin),
])
async def test_budget_stops_slow_port_and_preserves_earlier_findings(monkeypatch, module, cls):
    monkeypatch.setattr(module, '_HOST_BUDGET', 0.02)
    plugin = cls()
    finding = FindingData(plugin_id=plugin.id, severity=Severity.high, title='Test')

    async def probe(context, url, port, budget):
        if port == 80:
            return finding
        await asyncio.sleep(10)

    monkeypatch.setattr(plugin, '_test_host', probe)
    monkeypatch.setattr(module, 'is_web_port', lambda port: True)
    monkeypatch.setattr(module, 'web_scheme', lambda port: 'http')
    host = SimpleNamespace(ip='192.0.2.1', ports=[SimpleNamespace(number=p) for p in (80, 8080)])
    result = await asyncio.wait_for(plugin.check(None, host), timeout=1)
    assert result == [finding]
    assert result.incomplete_reason


@pytest.mark.parametrize('has_finding', [False, True])
async def test_engine_records_budget_exhaustion_as_incomplete(has_finding):
    finding = FindingData(plugin_id='test', severity=Severity.high, title='Test')
    findings = [finding] if has_finding else []
    plugin = SimpleNamespace(id='test', ports=None, name='Test', timeout=1,
                             check=AsyncMock(return_value=BudgetedFindings(
                                 findings, incomplete_reason='Budget exhausted')))
    context = SimpleNamespace(check_cancelled=Mock(), host_is_excluded=Mock(return_value=False),
                              log=SimpleNamespace(debug=AsyncMock(), warn=AsyncMock(), finding=AsyncMock()),
                              findings_count=0)
    host = SimpleNamespace(id='h1', ip='192.0.2.1', hostname=None)
    collector = SimpleNamespace(add_finding=AsyncMock())
    engine = ScanEngine('scan', None)
    engine._record_plugin_run = AsyncMock()
    await engine._run_plugin(plugin, context, host, None, collector, asyncio.Semaphore(1))
    recorded = engine._record_plugin_run.call_args.kwargs
    assert recorded['status'] == 'timeout'
    assert recorded['error'] == 'Budget exhausted'
    assert recorded['findings_count'] == len(findings)
    assert collector.add_finding.await_count == len(findings)
    coverage = build_coverage([SimpleNamespace(plugin_id='test', host_id='h1', **recorded)])
    assert coverage.checks_clean == 0
    assert coverage.checks_incomplete == 1
    assert coverage.per_plugin[0].findings_total == len(findings)
