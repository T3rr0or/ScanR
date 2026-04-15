import pytest
from scanr.utils.ip_utils import classify_target, expand_targets, is_private, is_valid_ip


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


def test_classify_target():
    assert classify_target("192.168.1.0/24") == "cidr"
    assert classify_target("192.168.1.1") == "ip"
    assert classify_target("example.com") == "hostname"
    assert classify_target("10.0.0.1-10.0.0.10") == "range"
