"""Hadoop YARN ResourceManager/NodeManager and HDFS NameNode exposure."""
from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import hadoop_exposure as he


class _Ctx:
    def proxy_config(self):
        return {}


def _install(monkeypatch, handler):
    def factory(context):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(he, "_client", factory)


def _routes(pages: dict, default=(404, "not found", None)):
    def handler(request):
        entry = pages.get(request.url.path, default)
        status, text, hdrs = (*entry, None)[:3] if len(entry) == 2 else entry
        return httpx.Response(status, text=text, headers=hdrs or {})
    return handler


def _host(port, state="open") -> SimpleNamespace:
    return SimpleNamespace(ip="192.0.2.100", hostname=None, ports=[SimpleNamespace(number=port, state=state, banner=None, service=None)])


async def _run(host):
    return await he.HadoopExposurePlugin().check(_Ctx(), host)


# ── YARN ResourceManager (port 8088) ────────────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_resource_manager_is_reported_as_critical_rce(monkeypatch):
    cluster_info = json.dumps({"clusterInfo": {
        "resourceManagerVersion": "3.3.4", "hadoopVersion": "3.3.4",
        "state": "STARTED", "haState": "ACTIVE",
    }})
    _install(monkeypatch, _routes({
        "/ws/v1/cluster/info": (200, cluster_info),
        "/ws/v1/cluster/apps": (200, '{"apps": {"app": []}}'),
    }))
    findings = await _run(_host(8088))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.critical
    assert "3.3.4" in finding.title
    assert "Remote Code Execution" in finding.title
    assert finding.cvss_score == 9.8


@pytest.mark.asyncio
async def test_resource_manager_kerberos_enforced_is_reported_as_info(monkeypatch):
    """Product present, auth enforced — never the critical RCE finding."""
    _install(monkeypatch, _routes({
        "/ws/v1/cluster/info": (401, "Unauthorized", {"www-authenticate": "Negotiate"}),
    }))
    findings = await _run(_host(8088))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.info
    assert "Authentication Enforced" in finding.title


@pytest.mark.asyncio
async def test_generic_401_protected_server_on_8088_produces_nothing(monkeypatch):
    """A 401 with no Negotiate challenge and no Hadoop /conf servlet must not
    be reported — a bare password-protected server is not evidence of Hadoop."""
    _install(monkeypatch, _routes({
        "/ws/v1/cluster/info": (401, "Unauthorized"),
        "/conf": (404, "Not Found"),
    }))
    assert await _run(_host(8088)) == []


# ── HDFS NameNode (port 9870 / 50070) ───────────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_webhdfs_listing_is_reported_as_critical(monkeypatch):
    jmx = json.dumps({"beans": [{
        "name": "Hadoop:service=NameNode,name=NameNodeInfo",
        "Version": "3.3.4, r...",
        "LiveNodes": '{"dn1": {}}',
    }]})
    _install(monkeypatch, _routes({
        "/jmx": (200, jmx),
        "/webhdfs/v1/": (200, '{"FileStatuses": {"FileStatus": [{"pathSuffix": "user"}]}}'),
    }))
    findings = await _run(_host(9870))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.critical
    assert "WebHDFS Filesystem Readable Without Authentication" in finding.title
    assert "3.3.4" in finding.title


@pytest.mark.asyncio
async def test_namenode_metadata_without_webhdfs_is_reported_as_high(monkeypatch):
    jmx = json.dumps({"beans": [{
        "name": "Hadoop:service=NameNode,name=NameNodeInfo",
        "Version": "3.3.4, r...",
    }]})
    _install(monkeypatch, _routes({
        "/jmx": (200, jmx),
        "/webhdfs/v1/": (403, "Forbidden"),
    }))
    findings = await _run(_host(9870))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert "Metadata Exposed Without Authentication" in finding.title


# ── YARN NodeManager (port 8042) ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_node_manager_is_reported_as_high(monkeypatch):
    node_info = json.dumps({"nodeInfo": {
        "nodeManagerVersion": "3.3.4", "hadoopVersion": "3.3.4", "id": "node1:45454",
    }})
    _install(monkeypatch, _routes({
        "/ws/v1/node/info": (200, node_info),
        "/ws/v1/node/containers": (200, '{"containers": {"container": []}}'),
    }))
    findings = await _run(_host(8042))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert "NodeManager 3.3.4 Unauthenticated" in finding.title


# ── mandatory: unrelated web server produces nothing ────────────────────────

@pytest.mark.asyncio
async def test_unrelated_nginx_server_produces_nothing(monkeypatch):
    _install(monkeypatch, _routes({
        "/ws/v1/cluster/info": (404, "Not Found"),
    }))
    assert await _run(_host(8088)) == []


@pytest.mark.asyncio
async def test_generic_jmx_endpoint_without_namenode_info_produces_nothing(monkeypatch):
    """A JMX servlet from some other Java app must not be read as HDFS NameNode."""
    _install(monkeypatch, _routes({
        "/jmx": (200, '{"beans": [{"name": "java.lang:type=Memory"}]}'),
        "/dfshealth.html": (404, "Not Found"),
    }))
    assert await _run(_host(9870)) == []


# ── mandatory: connection errors produce nothing, not an exception ─────────

@pytest.mark.asyncio
async def test_unreachable_host_produces_nothing(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")
    _install(monkeypatch, handler)
    assert await _run(_host(8088)) == []
