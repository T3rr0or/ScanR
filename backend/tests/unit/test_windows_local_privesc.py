"""Windows local privilege-escalation misconfiguration detection.

Pins the unquoted-service-path logic (the part most prone to false positives) and
the finding severities, using a fabricated registry read.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.authenticated.windows_local_privesc import (
    PrivescFindings,
    UnquotedService,
    WindowsLocalPrivescPlugin,
    is_unquoted_vulnerable,
    truncations,
)


def _port(number=445, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.150"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def test_unquoted_path_with_space_outside_windows_is_vulnerable():
    assert is_unquoted_vulnerable(r"C:\Program Files\App Vendor\svc.exe -k run")


def test_quoted_path_is_safe():
    assert not is_unquoted_vulnerable(r'"C:\Program Files\App\svc.exe"')


def test_windows_directory_paths_are_excluded():
    assert not is_unquoted_vulnerable(r"C:\Windows\system32\svchost.exe -k netsvcs")


def test_driver_nt_path_is_excluded():
    assert not is_unquoted_vulnerable(r"\SystemRoot\System32\drivers\x.sys")


def test_spaces_only_in_arguments_are_safe():
    assert not is_unquoted_vulnerable(r"C:\nospace\app.exe -flag with spaces")


def test_truncations_are_the_attempted_paths():
    # One space in the path → one earlier truncation Windows would try.
    assert truncations(r"C:\Program Files\App\svc.exe") == [r"C:\Program.exe"]
    # Two spaces → two truncations, in order.
    assert truncations(r"C:\Program Files\App Vendor\svc.exe") == [
        r"C:\Program.exe", r"C:\Program Files\App.exe"
    ]


def _patch(monkeypatch, gathered):
    async def fake_gather(self, ip, port, cred):
        return gathered
    monkeypatch.setattr(WindowsLocalPrivescPlugin, "_gather", fake_gather)
    monkeypatch.setattr(
        "scanr.plugins.authenticated.windows_local_privesc.windows_credential",
        lambda ctx: SimpleNamespace(username="a", password="b", domain="", nt_hash=""),
    )


@pytest.mark.asyncio
async def test_always_install_elevated_both_halves_is_critical(monkeypatch):
    gathered = PrivescFindings(
        installer_elevated_machine=True,
        installer_elevated_users=["S-1-5-21-1-2-3-1001"],
    )
    _patch(monkeypatch, gathered)
    findings = await WindowsLocalPrivescPlugin().check(object(), _host([_port()]))
    installer = [f for f in findings if "AlwaysInstallElevated" in f.title]
    assert installer and installer[0].severity.value == "critical"


@pytest.mark.asyncio
async def test_autologon_password_is_critical(monkeypatch):
    _patch(monkeypatch, PrivescFindings(autologon_password_present=True,
                                        autologon_user="svc-admin"))
    findings = await WindowsLocalPrivescPlugin().check(object(), _host([_port()]))
    assert any(f.severity.value == "critical" and "Autologon" in f.title for f in findings)


@pytest.mark.asyncio
async def test_unquoted_service_is_medium(monkeypatch):
    _patch(monkeypatch, PrivescFindings(
        unquoted_services=[UnquotedService("Svc", r"C:\App Dir\svc.exe", [r"C:\App.exe"])],
        services_examined=50,
    ))
    findings = await WindowsLocalPrivescPlugin().check(object(), _host([_port()]))
    assert any("Unquoted" in f.title and f.severity.value == "medium" for f in findings)


@pytest.mark.asyncio
async def test_nothing_found_is_silent(monkeypatch):
    _patch(monkeypatch, PrivescFindings())
    assert await WindowsLocalPrivescPlugin().check(object(), _host([_port()])) == []
