"""Windows defensive posture reporting.

Pins the summary of missing protections, and that SMBv1 is raised as its own
higher-severity finding.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.authenticated.windows_defenses import (
    DefensePosture,
    WindowsDefensesPlugin,
)


def _port(number=445, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.170"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def test_summarise_lists_every_missing_protection():
    weaknesses = WindowsDefensesPlugin._summarise(DefensePosture(defender_disabled=True))
    assert any("Defender" in w for w in weaknesses)
    assert any("script-block" in w for w in weaknesses)
    assert any("Credential Guard" in w for w in weaknesses)


def test_fully_hardened_host_has_no_weaknesses():
    hardened = DefensePosture(
        ps_scriptblock_logging=True, ps_module_logging=True,
        lsa_ppl=True, credential_guard=True,
    )
    assert WindowsDefensesPlugin._summarise(hardened) == []


def _patch(monkeypatch, posture):
    async def fake_read(self, ip, port, cred):
        return posture
    monkeypatch.setattr(WindowsDefensesPlugin, "_read", fake_read)
    monkeypatch.setattr(
        "scanr.plugins.authenticated.windows_defenses.windows_credential",
        lambda ctx: SimpleNamespace(username="a", password="b", domain="", nt_hash=""),
    )


@pytest.mark.asyncio
async def test_smb1_is_a_separate_high_finding(monkeypatch):
    posture = DefensePosture(read_ok=True, smb1_enabled=True)
    posture.weaknesses = WindowsDefensesPlugin._summarise(posture)
    _patch(monkeypatch, posture)
    findings = await WindowsDefensesPlugin().check(object(), _host([_port()]))
    smb1 = [f for f in findings if f.title == "SMBv1 Enabled"]
    assert smb1 and smb1[0].severity.value == "high"


@pytest.mark.asyncio
async def test_defender_off_makes_posture_high(monkeypatch):
    posture = DefensePosture(read_ok=True, defender_disabled=True)
    posture.weaknesses = WindowsDefensesPlugin._summarise(posture)
    _patch(monkeypatch, posture)
    findings = await WindowsDefensesPlugin().check(object(), _host([_port()]))
    posture_findings = [f for f in findings if "Hardening" in f.title]
    assert posture_findings and posture_findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_fully_hardened_host_is_silent(monkeypatch):
    posture = DefensePosture(
        read_ok=True, ps_scriptblock_logging=True, ps_module_logging=True,
        lsa_ppl=True, credential_guard=True,
    )
    posture.weaknesses = WindowsDefensesPlugin._summarise(posture)
    _patch(monkeypatch, posture)
    assert await WindowsDefensesPlugin().check(object(), _host([_port()])) == []
