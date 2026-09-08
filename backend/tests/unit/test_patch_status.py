"""Pending security update counting over authenticated SSH.

apt-check's "total;security" output is the fast, authoritative path when it is
present; the tests pin that path plus the two negative cases that matter most
for an authenticated check: a fully patched host says nothing, and a host with
no recognised package manager says nothing rather than raising -- the absence
of apt/dnf/yum/apk is not itself a finding.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.authenticated import patch_status as ps

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
    monkeypatch.setattr(ps.PatchStatusPlugin, "_run_commands", fake)


# ── pending security updates ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pending_security_updates_are_reported_with_the_right_count(monkeypatch):
    _install(monkeypatch, {
        ps._DETECT_CMD: "apt-get\n",
        ps._APT_CHECK_CMD: "10;3",
    })
    findings = await ps.PatchStatusPlugin().check(_Ctx(_CRED), _host())

    assert len(findings) == 1
    assert findings[0].severity is Severity.medium
    assert findings[0].title == "Pending Security Updates (3)"
    assert "Total pending updates: 10" in findings[0].evidence
    assert "Security updates: 3" in findings[0].evidence


@pytest.mark.asyncio
async def test_large_security_backlog_is_high(monkeypatch):
    _install(monkeypatch, {
        ps._DETECT_CMD: "apt-get\n",
        ps._APT_CHECK_CMD: "40;30",
    })
    findings = await ps.PatchStatusPlugin().check(_Ctx(_CRED), _host())
    assert findings[0].severity is Severity.high
    assert findings[0].title == "Pending Security Updates (30)"


@pytest.mark.asyncio
async def test_fully_patched_host_produces_nothing(monkeypatch):
    _install(monkeypatch, {
        ps._DETECT_CMD: "apt-get\n",
        ps._APT_CHECK_CMD: "0;0",
    })
    findings = await ps.PatchStatusPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_no_package_manager_found_produces_nothing_not_an_error(monkeypatch):
    """The detection loop found none of apt-get/dnf/yum/apk -- that is a fact
    about the host, not a scan failure."""
    _install(monkeypatch, {ps._DETECT_CMD: ""})
    findings = await ps.PatchStatusPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_missing_credentials_produces_nothing(monkeypatch):
    findings = await ps.PatchStatusPlugin().check(_Ctx(None), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_unreachable_host_produces_nothing_not_an_exception(monkeypatch):
    _install(monkeypatch, {})
    findings = await ps.PatchStatusPlugin().check(_Ctx(_CRED), _host())
    assert findings == []
