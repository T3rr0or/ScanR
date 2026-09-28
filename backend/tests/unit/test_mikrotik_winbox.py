"""MikroTik Winbox exposure / CVE-2018-14847."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.services import mikrotik_winbox as mw


def test_is_vulnerable_boundaries():
    assert mw.is_vulnerable_14847((6, 40)) is True
    assert mw.is_vulnerable_14847((6, 42)) is True
    assert mw.is_vulnerable_14847((6, 42, 0)) is True
    assert mw.is_vulnerable_14847((6, 42, 1)) is False
    assert mw.is_vulnerable_14847((6, 43)) is False
    assert mw.is_vulnerable_14847((7, 1)) is False


def test_longterm_branch_backport_is_not_vulnerable():
    # 6.40.8 backported the fix even though it is below 6.42.1.
    assert mw.is_vulnerable_14847((6, 40, 8)) is False
    assert mw.is_vulnerable_14847((6, 40, 7)) is True
    assert mw.is_vulnerable_14847((6, 41)) is True  # 6.41 < 6.42.1, not in [6.40.8,6.42)


def test_floor_guards_against_garbage():
    assert mw.is_vulnerable_14847((3, 30)) is False


def test_extract_version_picks_routeros_token():
    # Ignores unrelated numbers, keeps the highest 6.x/7.x token.
    data = b"\x13\x00some 1.2.3 binary 6.42.12 dll list 6.40 x"
    assert mw._extract_ros_version(data) == "6.42.12"


def test_extract_version_none_when_absent():
    assert mw._extract_ros_version(b"\x00\x01\x02nothing here 1.0") is None


def _host(state="open"):
    return SimpleNamespace(ip="192.0.2.44", hostname=None,
                           ports=[SimpleNamespace(number=8291, state=state, banner=None, service=None)])


@pytest.mark.asyncio
async def test_vulnerable_version_is_high(monkeypatch):
    async def _probe(ip, port):
        return b"...RouterOS 6.40.5 winbox list..."
    monkeypatch.setattr(mw, "_winbox_probe", _probe)
    findings = await mw.MikrotikWinboxPlugin().check(object(), _host())
    assert len(findings) == 1
    assert findings[0].severity is Severity.high
    assert findings[0].cve_ids == ["CVE-2018-14847"]
    assert "6.40.5" in findings[0].title


@pytest.mark.asyncio
async def test_patched_version_is_low(monkeypatch):
    async def _probe(ip, port):
        return b"RouterOS 6.48.6 stable"
    monkeypatch.setattr(mw, "_winbox_probe", _probe)
    findings = await mw.MikrotikWinboxPlugin().check(object(), _host())
    assert len(findings) == 1
    assert findings[0].severity is Severity.low


@pytest.mark.asyncio
async def test_exposed_without_version_is_medium(monkeypatch):
    async def _probe(ip, port):
        return None  # port reachable but version unreadable
    monkeypatch.setattr(mw, "_winbox_probe", _probe)
    findings = await mw.MikrotikWinboxPlugin().check(object(), _host())
    assert len(findings) == 1
    assert findings[0].severity is Severity.medium
    assert "port exposed" in findings[0].title


@pytest.mark.asyncio
async def test_closed_port_yields_nothing(monkeypatch):
    async def _probe(ip, port):
        raise AssertionError("should not probe a closed port")
    monkeypatch.setattr(mw, "_winbox_probe", _probe)
    findings = await mw.MikrotikWinboxPlugin().check(object(), _host(state="closed"))
    assert findings == []


def test_index_request_has_no_traversal():
    # The scanner must never send the //./.. traversal the exploit uses.
    assert b"//./.." not in mw._WINBOX_INDEX_REQUEST
    assert b".." not in mw._WINBOX_INDEX_REQUEST
