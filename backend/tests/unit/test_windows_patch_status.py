"""Windows servicing and update-revision assessment.

Pins the end-of-servicing date comparison and the UBR-gap logic, including the
deliberate silence when the host is at or ahead of the reference revision.
"""
from __future__ import annotations

from datetime import date
from types import SimpleNamespace

import pytest

from scanr.plugins.authenticated.windows_patch_status import (
    RELEASES,
    WindowsBuild,
    WindowsPatchStatusPlugin,
    assess_servicing,
    assess_update_revision,
)


def _port(number=445, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.140"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def test_eol_release_flagged_by_date():
    release = RELEASES["9600"]           # 8.1 / 2012 R2, EoL 2023
    verdict = assess_servicing(release, date(2026, 9, 28))
    assert verdict is not None
    severity, days = verdict
    assert severity.value == "critical"  # more than a year past
    assert days > 365


def test_supported_release_is_not_flagged():
    release = RELEASES["20348"]          # Server 2022, supported until 2031
    assert assess_servicing(release, date(2026, 9, 28)) is None


def test_ubr_behind_is_flagged():
    release = RELEASES["17763"]          # latest_ubr 7792 in the table
    verdict = assess_update_revision(release, 5000)
    assert verdict is not None
    _severity, gap = verdict
    assert gap == 7792 - 5000


def test_ubr_at_or_ahead_of_reference_is_silent():
    release = RELEASES["17763"]
    assert assess_update_revision(release, 7792) is None
    assert assess_update_revision(release, 9999) is None    # newer than our data


def test_full_version_and_server_detection():
    build = WindowsBuild(build="17763", ubr=5000, installation_type="Server")
    assert build.full_version == "17763.5000"
    assert build.is_server


@pytest.mark.asyncio
async def test_eol_build_produces_finding(monkeypatch):
    async def fake_read(self, ip, port, cred):
        return WindowsBuild(build="7601", product_name="Windows Server 2008 R2",
                            installation_type="Server")
    monkeypatch.setattr(WindowsPatchStatusPlugin, "_read_build", fake_read)
    monkeypatch.setattr(
        "scanr.plugins.authenticated.windows_patch_status.windows_credential",
        lambda ctx: SimpleNamespace(username="a", password="b", domain="", nt_hash=""),
    )
    findings = await WindowsPatchStatusPlugin().check(object(), _host([_port()]))
    assert any("End of Servicing" in f.title for f in findings)


@pytest.mark.asyncio
async def test_unknown_build_is_not_guessed(monkeypatch):
    async def fake_read(self, ip, port, cred):
        return WindowsBuild(build="99999")
    monkeypatch.setattr(WindowsPatchStatusPlugin, "_read_build", fake_read)
    monkeypatch.setattr(
        "scanr.plugins.authenticated.windows_patch_status.windows_credential",
        lambda ctx: SimpleNamespace(username="a", password="b", domain="", nt_hash=""),
    )
    assert await WindowsPatchStatusPlugin().check(object(), _host([_port()])) == []


@pytest.mark.asyncio
async def test_no_credential_means_no_check(monkeypatch):
    monkeypatch.setattr(
        "scanr.plugins.authenticated.windows_patch_status.windows_credential",
        lambda ctx: None,
    )
    assert await WindowsPatchStatusPlugin().check(object(), _host([_port()])) == []
