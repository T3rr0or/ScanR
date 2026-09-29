"""LAPS deployment status.

Pins the managed/unmanaged verdict and that only a domain-joined unmanaged host
is raised above informational.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.authenticated.laps_status import (
    LapsState,
    LapsStatusPlugin,
    backup_directory_name,
)


def _port(number=445, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.160"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def test_active_windows_laps_is_managed():
    assert LapsState(windows_laps_active=True).managed


def test_legacy_laps_is_managed():
    assert LapsState(legacy_laps_enabled=True).managed


def test_policy_with_backup_directory_is_managed():
    assert LapsState(windows_laps_policy=True, backup_directory=2).managed


def test_policy_disabled_is_not_managed():
    assert not LapsState(windows_laps_policy=True, backup_directory=0).managed


def test_nothing_is_not_managed():
    assert not LapsState().managed


def test_backup_directory_names():
    assert backup_directory_name(1) == "Azure AD / Entra ID"
    assert backup_directory_name(2) == "Active Directory"
    assert backup_directory_name(None) == "not configured"


def _patch(monkeypatch, state):
    async def fake_read(self, ip, port, cred):
        return state
    monkeypatch.setattr(LapsStatusPlugin, "_read", fake_read)
    monkeypatch.setattr(
        "scanr.plugins.authenticated.laps_status.windows_credential",
        lambda ctx: SimpleNamespace(username="a", password="b", domain="", nt_hash=""),
    )


@pytest.mark.asyncio
async def test_domain_host_without_laps_is_medium(monkeypatch):
    _patch(monkeypatch, LapsState(read_ok=True, domain="CORP"))
    findings = await LapsStatusPlugin().check(object(), _host([_port()]))
    assert len(findings) == 1 and findings[0].severity.value == "medium"


@pytest.mark.asyncio
async def test_standalone_host_without_laps_is_low(monkeypatch):
    _patch(monkeypatch, LapsState(read_ok=True, domain=""))
    findings = await LapsStatusPlugin().check(object(), _host([_port()]))
    assert findings[0].severity.value == "low"


@pytest.mark.asyncio
async def test_managed_host_is_silent(monkeypatch):
    _patch(monkeypatch, LapsState(read_ok=True, windows_laps_active=True, domain="CORP"))
    assert await LapsStatusPlugin().check(object(), _host([_port()])) == []
