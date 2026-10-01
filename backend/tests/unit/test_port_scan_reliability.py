"""Port-scan failure modes found by a fresh-install test of v0.23.1.

- nmap refused -sS as the non-root worker ("requires root privileges") and
  the host was dropped instead of falling back to TCP connect.
- A scan where every live host's port scan errored finished as "completed"
  with 0 findings, so `scanr ci` passed the build.
- masscan 1.3.2 finished its sweep and then never exited, holding the scan
  for the 3600s timeout; its buffered output file was empty when killed.
- Top-N port scans never covered plugin ports missing from nmap-services
  (ArangoDB 8529), so those plugins never ran.
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
import time
from types import SimpleNamespace

import pytest

from scanr.core.context import ScanContext
from scanr.core.engine import port_scan_failure
from scanr.scanner.port_scanner import nmap_wrapper
from scanr.scanner.port_scanner.masscan_wrapper import MasscanWrapper
from scanr.scanner.port_scanner.nmap_ports import _parse_top_tcp, compress_ports
from scanr.scanner.port_scanner.nmap_wrapper import NmapWrapper


class _Log:
    def __init__(self):
        self.lines: list[tuple[str, str]] = []

    async def _add(self, level, msg, **_):
        self.lines.append((level, msg))

    async def info(self, msg, **kw):
        await self._add("info", msg, **kw)

    async def warn(self, msg, **kw):
        await self._add("warn", msg, **kw)

    async def error(self, msg, **kw):
        await self._add("error", msg, **kw)

    async def debug(self, msg, **kw):
        await self._add("debug", msg, **kw)


def _nmap_context(scanners):
    async def _not_excluded(_ip):
        return False

    return SimpleNamespace(
        target_is_excluded=_not_excluded,
        excluded_ports=lambda: [],
        get_port_range=lambda: "--top-ports 1000",
        port_scanning_config=lambda: {"scanners": scanners, "firewall_strategy": "default"},
        performance_config=lambda: {"timeout": 60},
        profile_json=lambda: {},
        discovery_config=lambda: {},
        log=_Log(),
        port_scan_errors={},
    )


def _fake_nmap(monkeypatch, outcomes):
    """Replace nmap execution: `outcomes` maps a scan flag to a result or exception."""
    calls: list[str] = []

    async def fake_run(self, ip, args):
        calls.append(args)
        flag = "-sS" if "-sS" in args else "-sT" if "-sT" in args else "-sU"
        outcome = outcomes[flag]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(NmapWrapper, "_run_nmap", fake_run)
    return calls


_OPEN_REDIS = {"address": "10.0.0.5", "ports": [{"number": 6379, "protocol": "tcp", "state": "open"}]}


def test_syn_privilege_error_falls_back_to_tcp_connect(monkeypatch):
    monkeypatch.setattr(nmap_wrapper, "nmap_can_use_raw_sockets", lambda: True)
    calls = _fake_nmap(monkeypatch, {
        "-sS": RuntimeError("You requested a scan type which requires root privileges.\nQUITTING!"),
        "-sT": dict(_OPEN_REDIS),
    })
    ctx = _nmap_context(["syn"])

    result = asyncio.run(NmapWrapper().scan_host("10.0.0.5", ctx))

    assert result["ports"][0]["number"] == 6379
    assert any("-sT" in c for c in calls)
    assert ctx.port_scan_errors == {}


def test_syn_without_raw_sockets_runs_tcp_connect_once(monkeypatch):
    monkeypatch.setattr(nmap_wrapper, "nmap_can_use_raw_sockets", lambda: False)
    calls = _fake_nmap(monkeypatch, {"-sT": dict(_OPEN_REDIS)})

    result = asyncio.run(NmapWrapper().scan_host("10.0.0.5", _nmap_context(["syn", "tcp_connect"])))

    assert result is not None
    assert len(calls) == 1 and "-sT" in calls[0] and "--privileged" not in calls[0]


def test_raw_sockets_add_privileged_flag_for_non_root(monkeypatch):
    monkeypatch.setattr(nmap_wrapper, "nmap_can_use_raw_sockets", lambda: True)
    monkeypatch.setattr(nmap_wrapper.os, "geteuid", lambda: 1000)
    calls = _fake_nmap(monkeypatch, {"-sS": dict(_OPEN_REDIS)})

    asyncio.run(NmapWrapper().scan_host("10.0.0.5", _nmap_context(["syn"])))

    assert calls[0].startswith("--privileged -sS")


def test_every_scan_type_erroring_is_recorded(monkeypatch):
    monkeypatch.setattr(nmap_wrapper, "nmap_can_use_raw_sockets", lambda: True)
    _fake_nmap(monkeypatch, {
        "-sS": RuntimeError("'You requested a scan type which requires root privileges.\\nQUITTING!\\n'"),
        "-sT": RuntimeError("socket troubles"),
    })
    ctx = _nmap_context(["syn"])

    assert asyncio.run(NmapWrapper().scan_host("10.0.0.5", ctx)) is None
    error = ctx.port_scan_errors["10.0.0.5"]
    assert "requires root privileges" in error and "socket troubles" in error
    assert "QUITTING" not in error


def test_host_down_is_not_an_error(monkeypatch):
    monkeypatch.setattr(nmap_wrapper, "nmap_can_use_raw_sockets", lambda: False)
    _fake_nmap(monkeypatch, {"-sT": None})
    ctx = _nmap_context(["tcp_connect"])

    assert asyncio.run(NmapWrapper().scan_host("10.0.0.5", ctx)) is None
    assert ctx.port_scan_errors == {}


def test_scan_fails_only_when_no_live_host_could_be_scanned():
    errors = {"10.0.0.5": "nmap syn scan failed: requires root privileges"}
    message = port_scan_failure(live_hosts=13, hosts_scanned=0, errors=errors)
    assert message and "10.0.0.5" in message and "root privileges" in message
    # Partial success completes (with a warning from the engine).
    assert port_scan_failure(live_hosts=13, hosts_scanned=1, errors=errors) is None
    # Hosts that answered with nothing are a valid, clean result.
    assert port_scan_failure(live_hosts=13, hosts_scanned=0, errors={}) is None
    assert port_scan_failure(live_hosts=0, hosts_scanned=0, errors=errors) is None


def test_raw_socket_probe_reads_file_capability(monkeypatch):
    monkeypatch.setattr(nmap_wrapper.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(nmap_wrapper.shutil, "which", lambda _name: "/usr/bin/nmap")
    status = {"CapBnd": "00000000a80425fb", "NoNewPrivs": "0"}
    monkeypatch.setattr(nmap_wrapper, "_proc_status_field", lambda name: status.get(name))
    # VFS_CAP_REVISION_2 | effective, permitted = CAP_NET_RAW
    cap_net_raw = (0x02000000 | 1).to_bytes(4, "little") + (1 << 13).to_bytes(4, "little") + bytes(12)
    monkeypatch.setattr(nmap_wrapper.os, "getxattr", lambda *_: cap_net_raw, raising=False)

    probe = nmap_wrapper.nmap_can_use_raw_sockets.__wrapped__
    assert probe() is True

    status["NoNewPrivs"] = "1"  # file capabilities are ignored under no_new_privs
    assert probe() is False
    status["NoNewPrivs"] = "0"
    status["CapBnd"] = "0000000000000000"  # NET_RAW dropped from the container
    assert probe() is False


def test_parse_masscan_discovery_lines():
    parse = MasscanWrapper.parse_discovery_line
    assert parse("Discovered open port 6379/tcp on 172.29.77.20          \n") == ("172.29.77.20", 6379)
    assert parse("Discovered open port 53/udp on 10.0.0.1") is None
    assert parse("rate:  0.00-kpps, 100.00% done, waiting -84-secs, found=2") is None


@pytest.fixture
def hanging_masscan(tmp_path, monkeypatch):
    """A masscan stand-in that reports two ports, then never exits (like 1.3.2)."""
    script = tmp_path / "masscan"
    script.write_text(
        "#!/bin/sh\n"
        "echo 'Discovered open port 22/tcp on 10.0.0.5'\n"
        "echo 'Discovered open port 6379/tcp on 10.0.0.5'\n"
        "echo 'Scanning 1 hosts [2 ports/host]' >&2\n"
        "printf 'rate:  0.00-kpps, 100.00%% done,   0:00:00 remaining, found=2       \\r' >&2\n"
        "for s in 3 2 1 0 -1 -2 -3 -4 -5 -6; do\n"
        "  printf 'rate:  0.00-kpps, 100.00%% done, waiting %s-secs, found=2       \\r' \"$s\" >&2\n"
        "done\n"
        "exec sleep 3600\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")


def test_masscan_that_never_exits_is_stopped_with_results(hanging_masscan):
    ctx = SimpleNamespace(
        exclusion_policy=None,
        excluded_ports=lambda: [],
        performance_config=lambda: {},
        log=_Log(),
    )
    started = time.monotonic()

    result = asyncio.run(MasscanWrapper().scan(["10.0.0.5"], "-p 22,6379", ctx))

    assert result == {"10.0.0.5": [22, 6379]}
    assert time.monotonic() - started < 10
    messages = [m for _, m in ctx.log.lines]
    assert any("did not exit" in m for m in messages)
    # The countdown is summarised once, not logged per stderr update.
    assert sum("waiting" in m for m in messages) == 1


def test_top_ports_parse_and_compress():
    services = [
        "# comment",
        "http\t80/tcp\t0.484143",
        "unknown\t8529/udp\t0.000100",
        "ssh\t22/tcp\t0.182286",
        "https\t443/tcp\t0.208669",
        "domain\t53/udp\t0.213496",
    ]
    assert _parse_top_tcp(services, 2) == (80, 443)
    assert compress_ports([22, 80, 81, 82, 443, 8529, 81, 0, 70000]) == "22,80-82,443,8529"


def test_top_n_scan_includes_plugin_ports(monkeypatch):
    from scanr.scanner.port_scanner import nmap_ports

    monkeypatch.setattr(nmap_ports, "top_tcp_ports", lambda n: (80, 443, 22)[:n])

    class _Scan:
        profile_json = json.dumps({"port_range": "top-1000"})

    ctx = ScanContext.__new__(ScanContext)
    ctx.profile = "custom"
    ctx.scan = _Scan()
    ctx.plugin_ports = []
    assert ctx.get_port_range() == "--top-ports 1000"

    ctx.plugin_ports = [8529, 6379]
    assert ctx.get_port_range() == "-p 22,80,443,6379,8529"

    monkeypatch.setattr(nmap_ports, "top_tcp_ports", lambda n: None)  # no nmap-services
    assert ctx.get_port_range() == "--top-ports 1000"


def test_denylist_resolution_runs_in_parallel(monkeypatch):
    from scanr.utils import ip_utils

    def slow_getaddrinfo(name, *_args, **_kw):
        time.sleep(0.4)  # a Compose name this container cannot see
        raise OSError("Name or service not known")

    monkeypatch.setattr(ip_utils.socket, "getaddrinfo", slow_getaddrinfo)
    names = frozenset(f"svc-{i}" for i in range(8))
    started = time.monotonic()
    assert ip_utils._denylist_hostname_ips.__wrapped__(names) == frozenset()
    assert time.monotonic() - started < 1.5


def test_scan_read_reports_duration():
    from datetime import datetime, timedelta, timezone

    from scanr.schemas.scan import ScanSummary

    start = datetime(2026, 9, 30, 18, 32, 52, tzinfo=timezone.utc)
    base = dict(
        id="s", name="n", status="completed", profile="custom", created_at=start,
        hosts_total=1, hosts_up=1, findings_critical=0, findings_high=0,
        findings_medium=0, findings_low=0, findings_info=0,
    )
    done = ScanSummary(**base, started_at=start, finished_at=start + timedelta(seconds=95.6))
    assert done.duration_s == 96
    assert done.model_dump()["duration_s"] == 96
    running = ScanSummary(**base, started_at=start, finished_at=None)
    assert running.duration_s is None


def test_long_port_lists_are_summarised_in_logs():
    from scanr.scanner.port_scanner.nmap_ports import summarize_port_spec

    long_spec = compress_ports(range(1, 20000, 2))
    assert summarize_port_spec(f"-sT -sV -p {long_spec} --host-timeout 60s") == (
        "-sT -sV -p <10000 ports> --host-timeout 60s"
    )
    assert summarize_port_spec("-sT -p 80,443") == "-sT -p 80,443"


def test_detection_host_timeout_keeps_open_ports(monkeypatch):
    """nmap drops every port of a host that blows --host-timeout; -sV on an
    unidentifiable service (ArangoDB 8529) takes ~55s on its own."""
    monkeypatch.setattr(nmap_wrapper, "nmap_can_use_raw_sockets", lambda: True)
    calls: list[str] = []

    async def fake_run(self, ip, args):
        calls.append(args)
        if "-sV" in args.split():
            raise nmap_wrapper.NmapHostTimeout(ip)
        return {"address": ip, "ports": [{"number": 8529, "protocol": "tcp", "state": "open"}]}

    monkeypatch.setattr(NmapWrapper, "_run_nmap", fake_run)
    ctx = _nmap_context(["syn"])

    result = asyncio.run(NmapWrapper().scan_host("10.0.0.30", ctx))

    assert result["ports"][0]["number"] == 8529
    assert "-sV" not in calls[-1].split() and "-O" not in calls[-1].split()
    assert "-sS" in calls[-1]  # same scan type, only detection dropped
    assert ctx.port_scan_errors == {}
    assert any("host timeout" in m for _, m in ctx.log.lines)
