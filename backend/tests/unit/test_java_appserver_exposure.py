"""JBoss / WebLogic management and deserialization exposure."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import java_appserver_exposure as ja


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, routes, default=(404, "not found", None, b"")):
    """routes: path -> (status, text, headers|None, content|None)."""
    def handler(request):
        entry = routes.get(request.url.path, default)
        status, text, hdrs, content = (list(entry) + [None, None, None])[:4]
        kwargs = {"headers": hdrs or {}}
        if content is not None:
            kwargs["content"] = content
        else:
            kwargs["text"] = text or ""
        return httpx.Response(status, **kwargs)

    def factory(context):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(ja, "_client", factory)


def _host(port=8080):
    return SimpleNamespace(ip="192.0.2.30", hostname=None,
                           ports=[SimpleNamespace(number=port, state="open", banner=None, service=None)])


async def _run(host):
    return await ja.JavaAppserverExposurePlugin().check(_Ctx(), host)


@pytest.mark.asyncio
async def test_open_jmx_console_is_critical(monkeypatch):
    _install(monkeypatch, {
        "/jmx-console/": (200, "<html><title>JBoss JMX Management Console</title> MBean View</html>", None, None),
    })
    findings = await _run(_host())
    jmx = [f for f in findings if "JMX console" in f.title]
    assert len(jmx) == 1
    assert jmx[0].severity is Severity.critical
    assert jmx[0].cve_ids == ["CVE-2010-0738"]


@pytest.mark.asyncio
async def test_jmx_console_requiring_login_is_not_reported(monkeypatch):
    _install(monkeypatch, {
        # Auth enforced: a login form with j_username, not the console itself.
        "/jmx-console/": (200, "<form><input name='j_username'></form> jboss", None, None),
    })
    findings = await _run(_host())
    assert not any("console" in f.title for f in findings)


@pytest.mark.asyncio
async def test_invoker_serialized_object_is_critical(monkeypatch):
    _install(monkeypatch, {
        "/invoker/JMXInvokerServlet": (200, "", {"content-type": "application/x-java-serialized-object"},
                                       ja._JAVA_SERIAL_MAGIC + b"\x00\x00"),
    })
    findings = await _run(_host())
    inv = [f for f in findings if "invoker" in f.title]
    assert len(inv) == 1
    assert inv[0].severity is Severity.critical


@pytest.mark.asyncio
async def test_invoker_magic_bytes_without_content_type(monkeypatch):
    _install(monkeypatch, {
        "/invoker/EJBInvokerServlet": (200, "", None, ja._JAVA_SERIAL_MAGIC + b"payload"),
    })
    findings = await _run(_host())
    assert any("invoker" in f.title for f in findings)


@pytest.mark.asyncio
async def test_weblogic_wsat_endpoint_is_critical(monkeypatch):
    _install(monkeypatch, {
        "/wls-wsat/CoordinatorPortType": (500, "<soap:Envelope>CoordinatorPortType wsat fault</soap:Envelope>", None, None),
    })
    findings = await _run(_host(port=7001))
    wl = [f for f in findings if "deserialization endpoint" in f.title]
    assert len(wl) == 1
    assert wl[0].cve_ids == ["CVE-2017-10271"]


@pytest.mark.asyncio
async def test_weblogic_console_exposed_is_medium(monkeypatch):
    _install(monkeypatch, {
        "/console/login/LoginForm.jsp": (200, "<html>WebLogic Server Administration Console wl_login</html>", None, None),
    })
    findings = await _run(_host(port=7001))
    con = [f for f in findings if "administration console" in f.title]
    assert len(con) == 1
    assert con[0].severity is Severity.medium


@pytest.mark.asyncio
async def test_clean_server_yields_nothing(monkeypatch):
    _install(monkeypatch, {})  # everything 404s
    assert await _run(_host()) == []


@pytest.mark.asyncio
async def test_plain_html_invoker_is_not_a_finding(monkeypatch):
    # A 200 with ordinary HTML (no serialized magic / content-type) must not match.
    _install(monkeypatch, {
        "/invoker/JMXInvokerServlet": (200, "<html>Not Found</html>", None, None),
    })
    assert not any("invoker" in f.title for f in await _run(_host()))
