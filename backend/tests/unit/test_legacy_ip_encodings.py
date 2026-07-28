"""Legacy numeric IP encodings must not slip past the scope denylist.

'2130706433', '0x7f000001', '017700000001' and '127.1' are all rejected by
ipaddress.ip_address(), so a string-based denylist check treated them as ordinary
hostnames and let them through — while glibc's getaddrinfo happily resolves every
one of them to 127.0.0.1.
"""
import pytest

from scanr.utils.ip_utils import (
    canonical_ip,
    classify_target,
    expand_targets,
    is_forbidden_target,
)

# value -> the address it actually resolves to
LEGACY_LOOPBACK = {
    "2130706433": "127.0.0.1",
    "0x7f000001": "127.0.0.1",
    "017700000001": "127.0.0.1",
    "127.1": "127.0.0.1",
    "0177.1": "127.0.0.1",
    "127.0.1": "127.0.0.1",
    "0": "0.0.0.0",
}


@pytest.mark.parametrize("value,expected", LEGACY_LOOPBACK.items())
def test_canonical_ip_normalizes_legacy_forms(value, expected):
    assert canonical_ip(value) == expected


@pytest.mark.parametrize("value", LEGACY_LOOPBACK)
def test_legacy_loopback_forms_are_forbidden(value):
    assert is_forbidden_target(value), f"{value!r} must be rejected"


@pytest.mark.parametrize("value", LEGACY_LOOPBACK)
def test_legacy_forms_expand_to_canonical_ip(value):
    assert list(expand_targets(value)) == [LEGACY_LOOPBACK[value]]


@pytest.mark.parametrize("value", LEGACY_LOOPBACK)
def test_legacy_forms_classify_as_ip_not_hostname(value):
    assert classify_target(value) == "ip"


def test_legacy_metadata_encodings_are_forbidden():
    """169.254.169.254 in decimal is 2852039166."""
    assert canonical_ip("2852039166") == "169.254.169.254"
    assert is_forbidden_target("2852039166")


@pytest.mark.parametrize("value", [
    "example.com", "scanner.internal", "a.example.com", "host-1.example.com",
    "veryhost", "12ab", "foo.1", "1.2.3.4.5", "999.1",
])
def test_real_hostnames_are_not_treated_as_ips(value):
    assert canonical_ip(value) is None
    assert classify_target(value) == "hostname"


@pytest.mark.parametrize("value", ["8.8.8.8", "192.0.2.10", "2001:db8::1", "::1"])
def test_standard_ips_still_canonicalize(value):
    import ipaddress
    assert canonical_ip(value) == str(ipaddress.ip_address(value))


def test_routable_ips_are_not_forbidden():
    """Normalization must not start rejecting legitimate targets."""
    for value in ("8.8.8.8", "192.0.2.10", "198.51.100.5", "10.0.0.5", "2001:db8::1"):
        assert not is_forbidden_target(value), value


def test_ipv4_mapped_ipv6_loopback_is_forbidden():
    assert is_forbidden_target("::ffff:127.0.0.1")
    assert is_forbidden_target("::ffff:169.254.169.254")


def test_denylist_hostnames_are_matched_by_resolved_ip(monkeypatch):
    """A denylisted service reached by its container IP must still be blocked."""
    import socket

    import scanr.utils.ip_utils as ip_utils

    ip_utils._denylist_hostname_ips.cache_clear()

    def fake_getaddrinfo(host, *a, **kw):
        if host == "postgres":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.18.0.3", 0))]
        raise OSError("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    try:
        denylist = {"postgres", "redis"}
        # By name (already worked) and by resolved IP (previously bypassed).
        assert is_forbidden_target("postgres", denylist)
        assert is_forbidden_target("172.18.0.3", denylist)
        # A different address on the same private network is still scannable —
        # private ranges are legitimate targets for an internal scanner.
        assert not is_forbidden_target("172.18.0.99", denylist)
    finally:
        ip_utils._denylist_hostname_ips.cache_clear()


def test_denylist_ip_check_survives_unresolvable_names(monkeypatch):
    """Resolution failure must not raise or wrongly forbid."""
    import socket

    import scanr.utils.ip_utils as ip_utils

    ip_utils._denylist_hostname_ips.cache_clear()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: (_ for _ in ()).throw(OSError()))
    try:
        assert not is_forbidden_target("192.0.2.10", {"postgres"})
    finally:
        ip_utils._denylist_hostname_ips.cache_clear()
