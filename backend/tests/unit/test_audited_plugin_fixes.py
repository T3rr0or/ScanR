from __future__ import annotations

import asyncio
import json
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from scanr.plugins.cve import nvd_loader
from scanr.plugins.network import ipv6_discovery, subdomain_enum
from scanr.plugins.nuclei.nuclei_runner import NucleiRunnerPlugin
from scanr.plugins.ssh.ssh_algos import SshAlgosPlugin
from scanr.plugins.ssh.ssh_default_creds import SshDefaultCredsPlugin
from scanr.plugins.ssh.ssh_version import SshVersionPlugin


@pytest.mark.asyncio
async def test_ipv6_neighbor_discovery_does_not_leak_local_neighbors_in_single_host_internal_scan():
    plugin = ipv6_discovery.Ipv6DiscoveryPlugin()
    context = SimpleNamespace(profile_json=lambda: {"scan_context": "internal"})

    assert await plugin.check(context, SimpleNamespace(ip="192.0.2.1", ports=[])) == []


@pytest.mark.asyncio
async def test_subdomain_enum_takeover_check_receives_context_and_emits_finding(monkeypatch):
    monkeypatch.setattr(subdomain_enum, "_follow_cname", lambda _name: "bucket.s3.amazonaws.com")

    class Response:
        status_code = 404
        text = "not found"

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url):
            return Response()

    monkeypatch.setattr("httpx.AsyncClient", Client)
    context = SimpleNamespace(proxy_config=lambda: {})

    findings = await subdomain_enum.SubdomainEnumPlugin()._check_takeovers(
        context, ["shop.example.com"]
    )

    assert len(findings) == 1
    assert findings[0].plugin_id == "network.subdomain_takeover"


def test_ssh_version_cve_ranges_do_not_attribute_regresshion_to_older_versions():
    plugin = SshVersionPlugin()

    old_server = plugin._analyse_banner("SSH-2.0-OpenSSH_8.4p1", "192.0.2.1", 22)
    affected_server = plugin._analyse_banner("SSH-2.0-OpenSSH_8.5p1", "192.0.2.1", 22)

    assert old_server is not None
    assert "CVE-2024-6387" not in old_server.cve_ids
    assert affected_server is not None
    assert affected_server.cve_ids == ["CVE-2024-6387"]


@pytest.mark.asyncio
async def test_ssh_algorithms_report_weak_macs(monkeypatch):
    plugin = SshAlgosPlugin()
    monkeypatch.setattr(
        plugin,
        "_get_ssh_algos",
        AsyncMock(return_value={
            "kex_algorithms": [],
            "encryption_algorithms_server_to_client": [],
            "mac_algorithms_server_to_client": ["hmac-md5"],
        }),
    )
    host = SimpleNamespace(
        ip="192.0.2.1",
        ports=[SimpleNamespace(number=22, state="open")],
    )

    findings = await plugin.check(None, host)

    assert len(findings) == 1
    assert findings[0].title == "Weak SSH Message Authentication Codes"


def test_ssh_default_creds_honors_stop_on_success_false(monkeypatch):
    class FakeClient:
        def set_missing_host_key_policy(self, _policy):
            pass

        def connect(self, *_args, **_kwargs):
            pass

        def close(self):
            pass

    fake_paramiko = types.SimpleNamespace(
        SSHClient=FakeClient,
        AutoAddPolicy=object,
        AuthenticationException=type("AuthenticationException", (Exception,), {}),
    )
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)
    plugin = SshDefaultCredsPlugin()

    found = plugin._ssh_sync_list(
        "192.0.2.1", 22, [("a", "1"), ("b", "2")], 5, 0, False
    )

    assert found == [("a", "1"), ("b", "2")]


@pytest.mark.asyncio
async def test_nuclei_redacts_auth_headers_in_logged_command(monkeypatch):
    captured: dict[str, object] = {}

    class Process:
        async def communicate(self):
            return b"", None

    async def create_process(*args, **kwargs):
        captured["args"] = args
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)

    class Log:
        def __init__(self):
            self.messages = []

        async def info(self, message, **_kwargs):
            self.messages.append(message)

    log = Log()
    context = SimpleNamespace(
        web_auth_headers=lambda: {"Authorization": "Bearer secret-token"},
        log=log,
    )

    await NucleiRunnerPlugin()._run_nuclei("http://192.0.2.1:80", 80, context)

    args = captured["args"]
    assert "Authorization: Bearer secret-token" in args
    assert "secret-token" not in " ".join(log.messages)
    assert "<redacted>" in " ".join(log.messages)


def test_nvd_matching_requires_exact_non_wildcard_cpe_version(tmp_path, monkeypatch):
    db_path = tmp_path / "nvd.db"
    monkeypatch.setattr(nvd_loader, "DB_PATH", db_path)
    monkeypatch.setattr(nvd_loader.settings, "nvd_cache_dir", tmp_path)
    conn = nvd_loader._get_conn()
    entries = [
        ("CVE-TEST-120", "cpe:2.3:a:vendor:product:1.20:*:*:*:*:*:*:*"),
        ("CVE-TEST-12", "cpe:2.3:a:vendor:product:1.2:*:*:*:*:*:*:*"),
        ("CVE-TEST-ANY", "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
    ]
    for cve_id, cpe in entries:
        conn.execute(
            "INSERT INTO cves VALUES (?, ?, ?, ?, ?, ?)",
            (cve_id, "test", None, None, "high", json.dumps([cpe])),
        )
        nvd_loader._index_cpe_products(conn, cve_id, [cpe])
    conn.commit()
    conn.close()

    matches = nvd_loader.search_by_product("product", "1.2")

    assert [item["cve_id"] for item in matches] == ["CVE-TEST-12"]
