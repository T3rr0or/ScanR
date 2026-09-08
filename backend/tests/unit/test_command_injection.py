"""OS command injection detection.

Two independent oracles, and the tests keep them honest in opposite directions:
the echo oracle must not fire on a server that merely reflects input, and the
timing oracle must not fire on a server that is uniformly slow.
"""
import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.web import command_injection as ci
from scanr.plugins.web._crawler import CrawlResult


class _Ctx:
    def proxy_config(self):
        return {}

    def web_auth_headers(self):
        return {}


@pytest.fixture(autouse=True)
def _no_crawl(monkeypatch):
    """Skip crawling; the plugin's own param list is what we exercise."""
    async def fake_crawl(base_url, client):
        return CrawlResult(paths=["/"], get_params=[])
    monkeypatch.setattr(ci, "crawl", fake_crawl)


def _install(monkeypatch, handler):
    def factory(*_a, **_kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ci, "create_web_client", factory)


async def _run(base="http://192.0.2.10:80", budget=None):
    from scanr.plugins.web._budget import Budget
    return await ci.CommandInjectionPlugin()._test_host(
        _Ctx(), base, 80, budget or Budget(300.0)
    )


# ── echo oracle ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_injection_when_the_marker_is_executed(monkeypatch):
    def handler(request):
        value = request.url.params.get("cmd", "")
        # Simulate a shell: run the echo and return only its output.
        if "echo" in value:
            marker = value.split("echo ")[1].split(")")[0].split("`")[0].strip("; ")
            return httpx.Response(200, text=f"PING output\n{marker}\n")
        return httpx.Response(200, text="PING output")

    _install(monkeypatch, handler)
    finding = await _run()

    assert finding is not None
    assert finding.severity is Severity.critical
    assert finding.title == "OS Command Injection"
    assert finding.cvss_score == 9.8


@pytest.mark.asyncio
async def test_pure_reflection_is_not_reported(monkeypatch):
    """A server echoing the raw query string back is not executing it."""
    def handler(request):
        return httpx.Response(200, text=f"You searched for: {request.url.query.decode()}")

    _install(monkeypatch, handler)
    assert await _run() is None


@pytest.mark.asyncio
async def test_marker_already_in_the_baseline_is_not_reported(monkeypatch):
    def handler(request):
        # Pathological: page contains something marker-shaped regardless.
        return httpx.Response(200, text="scanrdeadbeefcafe appears always")

    _install(monkeypatch, handler)
    assert await _run() is None


@pytest.mark.asyncio
async def test_clean_application_produces_nothing(monkeypatch):
    _install(monkeypatch, lambda r: httpx.Response(200, text="<html>hello</html>"))
    assert await _run() is None


@pytest.mark.asyncio
async def test_errors_do_not_propagate(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")

    _install(monkeypatch, handler)
    assert await _run() is None


# ── timing oracle ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_timing_oracle_requires_a_reproducible_delay(monkeypatch):
    """One slow response is noise; the delay must repeat to count."""
    calls = {"n": 0}

    async def fake_timed_get(client, url, params):
        value = list(params.values())[0]
        if "sleep" not in value and "ping" not in value:
            return 0.1
        calls["n"] += 1
        return 9.0 if calls["n"] == 1 else 0.1   # slow once, then fast

    monkeypatch.setattr(ci.CommandInjectionPlugin, "_timed_get", staticmethod(fake_timed_get))
    _install(monkeypatch, lambda r: httpx.Response(200, text="static"))
    assert await _run() is None


@pytest.mark.asyncio
async def test_timing_oracle_reports_a_consistent_delay(monkeypatch):
    async def fake_timed_get(client, url, params):
        value = list(params.values())[0]
        return 9.0 if ("sleep" in value or "ping" in value) else 0.1

    monkeypatch.setattr(ci.CommandInjectionPlugin, "_timed_get", staticmethod(fake_timed_get))
    _install(monkeypatch, lambda r: httpx.Response(200, text="static"))
    finding = await _run()

    assert finding is not None
    assert "Response time rose" in finding.evidence


@pytest.mark.asyncio
async def test_uniformly_slow_server_is_not_reported(monkeypatch):
    """A backend that is slow for every request has no timing differential."""
    async def fake_timed_get(client, url, params):
        return 9.0

    monkeypatch.setattr(ci.CommandInjectionPlugin, "_timed_get", staticmethod(fake_timed_get))
    _install(monkeypatch, lambda r: httpx.Response(200, text="static"))
    assert await _run() is None


def test_plugin_is_declared_intrusive_but_not_destructive():
    """It sends attack payloads, but echo and sleep change no state."""
    assert ci.CommandInjectionPlugin.intrusive is True
    assert ci.CommandInjectionPlugin.destructive is False
    assert ci.CommandInjectionPlugin.risk_intrusive() is True


def test_payloads_never_write_or_call_out():
    """Guard against a future payload that mutates the target."""
    marker_payloads = [p for p, _ in ci._echo_payloads("m")]
    all_payloads = marker_payloads + [p for p, _ in ci._delay_payloads()]
    forbidden = ("rm ", "curl", "wget", "nc ", ">", "mv ", "dd ", "mkfifo", "chmod")
    for payload in all_payloads:
        assert not any(bad in payload for bad in forbidden), payload


# ── time budget ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_an_exhausted_budget_stops_the_check(monkeypatch):
    """The plugin must stop itself rather than be cancelled by the engine.

    paths x params x the timing oracle can exceed the plugin's own 300s timeout
    on a slow host, and a cancelled check yields no partial result at all.
    """
    from scanr.plugins.web._budget import Budget

    asked = []

    def handler(request):
        asked.append(str(request.url))
        return httpx.Response(200, text="ok")

    _install(monkeypatch, handler)
    spent = Budget(0.0)
    assert await _run(budget=spent) is None
    assert spent.expired_early is True
    # The crawl still happens, but no parameter probing is attempted.
    assert not any("scanr_cmdi_baseline" in u for u in asked)


@pytest.mark.asyncio
async def test_a_thin_budget_skips_the_timing_oracle(monkeypatch):
    """The timing oracle stalls on purpose; never start one we cannot finish."""
    from scanr.plugins.web._budget import Budget

    called = {"timing": False}

    async def fake_timing(self, client, url, param):
        called["timing"] = True
        return None

    monkeypatch.setattr(ci.CommandInjectionPlugin, "_timing_probe", fake_timing)
    _install(monkeypatch, lambda r: httpx.Response(200, text="static"))

    await _run(budget=Budget(ci._SLEEP_SECONDS * 3 - 1))
    assert called["timing"] is False, "thin budget must not start the timing oracle"

    called["timing"] = False
    await _run(budget=Budget(300.0))
    assert called["timing"] is True, "a full budget must still run it"


def test_budget_is_inside_the_declared_plugin_timeout():
    """Stopping deliberately only works if we stop before the engine cancels us."""
    assert ci._HOST_BUDGET < ci.CommandInjectionPlugin.timeout
