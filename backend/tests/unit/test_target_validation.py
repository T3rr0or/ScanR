"""Regression: target-validation hardening in utils/ip_utils.py.

1. RFC-1123 hostname validation rejects option-injection targets ('-Pn',
   '--banners', 'foo-') that would otherwise be passed as argv to scanner
   subprocesses (nmap/masscan flag injection).
2. resolve_and_check_target flags hostnames that RESOLVE to forbidden
   addresses — the string-based denylist alone misses 'evil.example.com'
   pointing at 127.0.0.1 / 169.254.169.254.
"""
import socket

import pytest

from scanr.utils.ip_utils import (
    expand_targets,
    is_forbidden_target,
    is_valid_hostname,
    resolve_and_check_target,
)


@pytest.mark.parametrize("bad", ["-Pn", "--banners", "foo-", "-", "-evil.com", "a..b", "foo_bar.com", ""])
def test_invalid_hostnames_rejected(bad):
    assert not is_valid_hostname(bad)


@pytest.mark.parametrize("bad", ["-Pn", "--banners", "foo-"])
def test_expand_targets_rejects_option_injection(bad):
    with pytest.raises(ValueError):
        list(expand_targets(bad))


@pytest.mark.parametrize("good", ["scanme.example.org", "foo-bar.com", "a.b.c", "host1", "trailing.example.com."])
def test_valid_hostnames_accepted(good):
    assert is_valid_hostname(good)


def test_expand_targets_yields_plain_hostname():
    assert list(expand_targets("foo-bar.com")) == ["foo-bar.com"]


def test_forbidden_target_basics():
    assert is_forbidden_target("127.0.0.1")
    assert is_forbidden_target("169.254.169.254")
    assert is_forbidden_target("localhost")
    assert not is_forbidden_target("93.184.216.34")
    assert not is_forbidden_target("example.com")


def _gai_returning(ip: str):
    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    return fake


@pytest.mark.asyncio
async def test_resolve_and_check_flags_loopback_resolution(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _gai_returning("127.0.0.1"))
    assert await resolve_and_check_target("evil.example.com") is True


@pytest.mark.asyncio
async def test_resolve_and_check_flags_metadata_resolution(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _gai_returning("169.254.169.254"))
    assert await resolve_and_check_target("metadata.example.com") is True


@pytest.mark.asyncio
async def test_resolve_and_check_allows_public_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _gai_returning("93.184.216.34"))
    assert await resolve_and_check_target("good.example.com") is False


@pytest.mark.asyncio
async def test_resolve_and_check_unresolvable_returns_false(monkeypatch):
    def boom(*args, **kwargs):
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert await resolve_and_check_target("nope.invalid") is False
