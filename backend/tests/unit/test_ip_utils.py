from scanr.utils.ip_utils import (
    classify_target,
    expand_targets,
    is_forbidden_target,
    is_private,
    is_valid_ip,
)


def test_expand_single_ip():
    result = list(expand_targets("192.168.1.1"))
    assert result == ["192.168.1.1"]


def test_expand_cidr():
    result = list(expand_targets("192.168.1.0/30"))
    assert "192.168.1.1" in result
    assert "192.168.1.2" in result
    assert len(result) == 2


def test_expand_range():
    result = list(expand_targets("10.0.0.1-10.0.0.3"))
    assert result == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_expand_short_range():
    result = list(expand_targets("192.168.1.1-3"))
    assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_expand_hostname():
    result = list(expand_targets("example.com"))
    assert result == ["example.com"]


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1")
    assert is_valid_ip("::1")
    assert not is_valid_ip("not-an-ip")
    assert not is_valid_ip("256.0.0.1")


def test_is_private():
    assert is_private("192.168.1.1")
    assert is_private("10.0.0.1")
    assert is_private("172.16.0.1")
    assert not is_private("8.8.8.8")


def test_is_forbidden_target_addresses():
    # Loopback, link-local (incl. cloud metadata), unspecified, multicast
    assert is_forbidden_target("127.0.0.1")
    assert is_forbidden_target("::1")
    assert is_forbidden_target("169.254.169.254")  # cloud metadata
    assert is_forbidden_target("0.0.0.0")
    assert is_forbidden_target("224.0.0.1")
    # Routable / private targets are allowed (operator decides authorization)
    assert not is_forbidden_target("8.8.8.8")
    assert not is_forbidden_target("192.0.2.10")
    assert not is_forbidden_target("10.0.0.5")


def test_is_forbidden_target_hostnames():
    assert is_forbidden_target("localhost")
    assert is_forbidden_target("metadata.google.internal")
    assert is_forbidden_target("LOCALHOST")  # case-insensitive
    assert not is_forbidden_target("example.com")
    # Extra denylist (scanner infra service names)
    deny = {"postgres", "redis"}
    assert is_forbidden_target("postgres", deny)
    assert not is_forbidden_target("postgres")


def test_classify_target():
    assert classify_target("192.168.1.0/24") == "cidr"
    assert classify_target("192.168.1.1") == "ip"
    assert classify_target("example.com") == "hostname"
    assert classify_target("10.0.0.1-10.0.0.10") == "range"
