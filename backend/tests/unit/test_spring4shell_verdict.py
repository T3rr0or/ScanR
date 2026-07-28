"""Spring4Shell must not call a patched app vulnerable.

The probe POSTs class.module.classLoader.* binding parameters and read a
Spring-formatted HTTP 400 as confirmation of CVE-2022-22965, reporting critical
RCE. A 400 is Spring parsing the request and *refusing* the binding — what a
patched app does — so any Spring Boot app that 400s a POST to / was reported as
vulnerable. Acceptance is a lead worth reporting; rejection is not.
"""
import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.web.spring4shell_check import Spring4ShellCheckPlugin

SPRING_400 = (
    '{"timestamp":"2026-01-01T00:00:00.000+00:00","status":400,'
    '"error":"Bad Request","path":"/"}'
)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://t")


@pytest.mark.asyncio
async def test_spring_format_400_is_not_a_vulnerability():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={
            "timestamp": "2026-01-01T00:00:00.000+00:00",
            "status": 400, "error": "Bad Request", "path": "/",
        })

    plugin = Spring4ShellCheckPlugin()
    async with _client(handler) as client:
        result = await plugin._probe_spring4shell(client, "http://t", 8080)

    assert result is None, (
        "a Spring-format 400 means the binding was refused — reporting it as "
        "Spring4Shell flags every patched Spring app as critical RCE"
    )


@pytest.mark.asyncio
async def test_accepted_binding_is_reported_but_not_as_confirmed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    plugin = Spring4ShellCheckPlugin()
    async with _client(handler) as client:
        result = await plugin._probe_spring4shell(client, "http://t", 8080)

    assert result is not None, "an accepted classLoader binding is worth surfacing"
    # Exploitability additionally needs JDK 9+ and a WAR deployment, neither of
    # which this probe can see, so it must not claim a confirmed critical.
    assert result.severity is not Severity.critical
    assert "not confirmed" in result.title.lower() or "possible" in result.title.lower()
    assert "not confirmed" in result.evidence.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 404, 405, 500])
async def test_other_rejections_are_not_reported(status):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text="nope")

    plugin = Spring4ShellCheckPlugin()
    async with _client(handler) as client:
        result = await plugin._probe_spring4shell(client, "http://t", 8080)

    assert result is None


@pytest.mark.asyncio
async def test_probe_is_declared_destructive():
    """It rebinds Tomcat's AccessLogValve on a vulnerable target, so it must be
    excluded from safe scans and gated behind the agent's exploitation capability."""
    assert Spring4ShellCheckPlugin.destructive is True
    assert Spring4ShellCheckPlugin.risk_intrusive() is True
