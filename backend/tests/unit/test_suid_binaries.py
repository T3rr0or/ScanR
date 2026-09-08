"""Unexpected SUID/SGID binary discovery over authenticated SSH.

Pins the split that matters most: a GTFOBins-style interpreter/shell with SUID
root is always an escalation finding, while a binary a mainstream distro ships
SUID by design (sudo) in its normal system directory must never be reported on
its own — that would be pure noise on every scanned host.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.authenticated import suid_binaries as sb

_CRED = {"username": "root", "password": "hunter2"}


class _Ctx:
    def __init__(self, cred=None):
        self._cred = cred

    def credential(self, role):
        return self._cred

    @property
    def credential_data(self):
        return self._cred


def _host(port=22, state="open"):
    return SimpleNamespace(
        ip="192.0.2.10", hostname=None, ports=[SimpleNamespace(number=port, state=state)]
    )


def _install(monkeypatch, outputs: dict[str, str]):
    async def fake(self, ip, port, cred, commands):
        return {c: outputs[c] for c in commands if c in outputs}
    monkeypatch.setattr(sb.SuidBinariesPlugin, "_run_commands", fake)


# ── escalation vs baseline ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_gtfobins_style_binary_is_reported_high(monkeypatch):
    """`find` SUID root has a one-line GTFOBins entry to an interactive root
    shell -- this is not a subtle weakness."""
    line = "-rwsr-xr-x 1 0 0 157232 Jan 6 2022 /usr/bin/find"
    _install(monkeypatch, {sb._FIND_CMD: line})
    findings = await sb.SuidBinariesPlugin().check(_Ctx(_CRED), _host())

    assert len(findings) == 1
    assert findings[0].severity is Severity.high
    assert findings[0].title == "SUID Root Binaries Allowing Trivial Privilege Escalation"
    assert "/usr/bin/find" in findings[0].evidence


@pytest.mark.asyncio
async def test_baseline_sudo_in_its_normal_directory_is_not_reported(monkeypatch):
    """sudo is SUID root by design on every mainstream distro."""
    line = "-rwsr-xr-x 1 0 0 166056 Jan 6 2022 /usr/bin/sudo"
    _install(monkeypatch, {sb._FIND_CMD: line})
    findings = await sb.SuidBinariesPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_a_baseline_binary_outside_its_system_directory_is_reported(monkeypatch):
    """A SUID `mount` under /tmp is an impostor, not the distro's own copy."""
    line = "-rwsr-xr-x 1 0 0 43416 Jan 6 2022 /tmp/mount"
    _install(monkeypatch, {sb._FIND_CMD: line})
    findings = await sb.SuidBinariesPlugin().check(_Ctx(_CRED), _host())

    assert len(findings) == 1
    assert findings[0].title == "SUID/SGID Binaries Outside the Distribution Baseline"
    assert "/tmp/mount" in findings[0].evidence


@pytest.mark.asyncio
async def test_empty_command_output_produces_nothing(monkeypatch):
    _install(monkeypatch, {sb._FIND_CMD: ""})
    findings = await sb.SuidBinariesPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_missing_credentials_produces_nothing(monkeypatch):
    findings = await sb.SuidBinariesPlugin().check(_Ctx(None), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_unreachable_host_produces_nothing_not_an_exception(monkeypatch):
    _install(monkeypatch, {})
    findings = await sb.SuidBinariesPlugin().check(_Ctx(_CRED), _host())
    assert findings == []
