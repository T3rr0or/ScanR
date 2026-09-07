from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from scanr.core.scope_policy import ExclusionPolicy
from scanr.core.engine import _resolve_authorized_targets
from scanr.scanner.port_scanner.nmap_wrapper import NmapWrapper
from scanr.scanner.port_scanner.masscan_wrapper import MasscanWrapper


def _rule(kind: str, value: str):
    return SimpleNamespace(type=kind, value=value)


def test_exclusion_policy_matches_all_persisted_rule_types():
    policy = ExclusionPolicy.from_records([
        _rule("ip", "192.0.2.10"),
        _rule("cidr", "10.20.0.0/16"),
        _rule("host", "admin.example.test"),
        _rule("host", "*.fragile.example.test"),
        _rule("port", "tcp/22,443,8000-8002"),
    ])

    assert policy.excludes_ip("192.0.2.10")
    assert policy.excludes_ip("10.20.3.4")
    assert not policy.excludes_ip("10.21.3.4")
    assert policy.excludes_hostname("ADMIN.EXAMPLE.TEST.")
    assert policy.excludes_hostname("plc.fragile.example.test")
    assert not policy.excludes_hostname("fragile.example.test")
    assert {22, 443, 8000, 8001, 8002} <= policy.ports


@pytest.mark.parametrize(
    ("kind", "value"),
    [("ip", "not-ip"), ("cidr", "10.0.0.0/99"), ("host", "*.bad_host"),
     ("port", "0"), ("port", "9000-8000"), ("other", "x")],
)
def test_invalid_persisted_exclusion_fails_closed(kind, value):
    with pytest.raises(ValueError):
        ExclusionPolicy.from_records([_rule(kind, value)])


@pytest.mark.asyncio
async def test_hostname_is_excluded_when_dns_answer_hits_cidr(monkeypatch):
    policy = ExclusionPolicy.from_records([_rule("cidr", "10.50.0.0/16")])

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.50.1.7", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert await policy.excludes_target("target.example.test")


@pytest.mark.asyncio
async def test_filter_targets_preserves_order_and_reports_excluded():
    policy = ExclusionPolicy.from_records([
        _rule("ip", "192.0.2.2"),
        _rule("host", "skip.example.test"),
    ])
    allowed, excluded = await policy.filter_targets([
        "192.0.2.1", "192.0.2.2", "keep.example.test", "skip.example.test",
    ])
    assert allowed == ["192.0.2.1", "keep.example.test"]
    assert excluded == ["192.0.2.2", "skip.example.test"]


@pytest.mark.asyncio
async def test_resolution_pins_numeric_targets_and_preserves_hostname(monkeypatch):
    def fake_getaddrinfo(host, *_args, **_kwargs):
        assert host == "app.example.test"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = await _resolve_authorized_targets(
        ["app.example.test"], denylist=set(), exclusions=ExclusionPolicy()
    )
    assert result.targets == ["93.184.216.34"]
    assert result.hostname_by_ip == {"93.184.216.34": "app.example.test"}
    assert result.forbidden == []


@pytest.mark.asyncio
async def test_resolution_rejects_mixed_forbidden_dns_answers(monkeypatch):
    def fake_getaddrinfo(_host, *_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = await _resolve_authorized_targets(
        ["mixed.example.test"], denylist=set(), exclusions=ExclusionPolicy()
    )
    assert result.targets == []
    assert result.forbidden == ["mixed.example.test -> 127.0.0.1"]


@pytest.mark.asyncio
async def test_resolution_applies_configured_infrastructure_denylist(monkeypatch):
    infra_ip = "10.99.0.7"

    def fake_getaddrinfo(_host, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (infra_ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = await _resolve_authorized_targets(
        ["alias.example.test"],
        denylist={"unique-p0-infra.invalid"},
        exclusions=ExclusionPolicy(),
    )
    assert result.targets == []
    assert result.forbidden == [f"alias.example.test -> {infra_ip}"]


class _Log:
    async def warn(self, *_args, **_kwargs):
        return None

    async def info(self, *_args, **_kwargs):
        return None


class _Context:
    log = _Log()

    def __init__(self, *, target_excluded=False, excluded_ports=()):
        self._target_excluded = target_excluded
        self._excluded_ports = list(excluded_ports)

    async def target_is_excluded(self, _target):
        return self._target_excluded

    def excluded_ports(self):
        return self._excluded_ports

    def get_port_range(self):
        return "-p 1-1000"

    def discovery_config(self):
        return {"mode": "skip", "assume_up": True}

    def port_scanning_config(self):
        return {"scanners": ["tcp_connect"], "firewall_strategy": "default"}

    def performance_config(self):
        return {"timeout": 5}

    def profile_json(self):
        return {"enumeration": {"service_detection": False}}


@pytest.mark.asyncio
async def test_nmap_rechecks_host_and_port_exclusions_at_sink(monkeypatch):
    wrapper = NmapWrapper()
    called = False

    async def fake_run(_ip, _args):
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(wrapper, "_run_nmap", fake_run)
    assert await wrapper.scan_host("192.0.2.1", _Context(target_excluded=True)) is None
    assert called is False

    captured: list[str] = []

    async def capture(_ip, args):
        captured.append(args)
        return None

    monkeypatch.setattr(wrapper, "_run_nmap", capture)
    await wrapper.scan_host("192.0.2.1", _Context(excluded_ports=(22, 443)))
    assert captured
    assert "--exclude-ports 22,443" in captured[0]


def test_masscan_subtracts_excluded_ports_from_supported_port_spec():
    args = MasscanWrapper._without_excluded_ports(
        ["-p", "20-25,80,U:53-55"],
        [22, 24, 53, 80],
    )

    assert args == ["-p", "20-21,23,25,U:54-55"]
    assert "--exclude-ports" not in args


def test_masscan_skips_when_every_requested_port_is_excluded():
    assert MasscanWrapper._without_excluded_ports(["-p", "22,443"], [22, 443]) == []
