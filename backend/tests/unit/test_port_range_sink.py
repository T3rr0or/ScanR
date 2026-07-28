"""The scanner-argument sink must reject unsafe port specs on its own.

Even with every API writer validated, ScanContext.get_port_range() is the last
line before the value becomes nmap argv, so it re-checks. This covers rows that
reached the DB before validation existed, or by any non-API route.
"""
import json

import pytest

from scanr.core.context import ScanContext
from scanr.schemas.profile import is_safe_port_range


def _ctx(port_range, profile="standard"):
    class _FakeScan:
        profile_json = json.dumps({"port_range": port_range})

    ctx = ScanContext.__new__(ScanContext)
    ctx.profile = profile
    ctx.scan = _FakeScan()
    return ctx


@pytest.mark.parametrize("value", [
    "- --script /tmp/pwn.nse",
    "80 -oN /app/wordlists/x",
    "80,443 --datadir /tmp",
    "80\t--script vuln",
    "80\n--script vuln",
    "top-99999",
    "; rm -rf /",
    "$(id)",
    "",
])
def test_unsafe_port_ranges_rejected(value):
    assert not is_safe_port_range(value)


@pytest.mark.parametrize("value", ["top-1000", "top-10000", "all", "80", "80,443", "1-1024", "80,443,8000-8010"])
def test_safe_port_ranges_accepted(value):
    assert is_safe_port_range(value)


def test_sink_falls_back_to_profile_default_on_injection():
    """A malformed value must not reach argv — fall back to the profile default."""
    out = _ctx("- --script /tmp/pwn.nse").get_port_range()
    assert out == "--top-ports 10000"
    assert "--script" not in out


def test_sink_emits_no_whitespace_beyond_its_own_flag():
    """Whatever the sink emits must split into at most 2 nmap argv tokens."""
    import shlex

    for value in ["top-1000", "all", "80,443", "1-1024", "- --script /tmp/x", "80 -oN /a"]:
        assert len(shlex.split(_ctx(value).get_port_range())) <= 2


def test_sink_passes_through_valid_custom_spec():
    assert _ctx("80,443,8000-8010").get_port_range() == "-p 80,443,8000-8010"
    assert _ctx("all").get_port_range() == "-p-"
    assert _ctx("top-1000").get_port_range() == "--top-ports 1000"
