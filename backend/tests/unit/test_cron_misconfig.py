"""Cron privilege-escalation misconfiguration over authenticated SSH.

Both cases exercised here take the drop-in path (`/etc/cron.{hourly,...}/*`,
which always runs as root) rather than the root-crontab-plus-stat round trip:
the drop-in listing alone is a complete write-then-root-executes primitive,
and reaching a script through a crontab entry involves the plugin building its
own quoted `ls` command from the parsed job list -- exact-string matching that
command in a test would pin an implementation detail rather than behaviour.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.authenticated import cron_misconfig as cm

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
    monkeypatch.setattr(cm.CronMisconfigPlugin, "_run_commands", fake)


# ── writable cron target ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_world_writable_cron_script_is_reported(monkeypatch):
    """A world-writable script under /etc/cron.daily runs as root on the next
    tick -- no exploit needed, cron is doing exactly what it is told."""
    _install(monkeypatch, {
        cm._PERM_CMD: "",
        cm._CONTENT_CMD: "",
        cm._DROPIN_CMD: "-rwxrwxrwx 1 0 0 512 Jan 6 2022 /etc/cron.daily/backup.sh",
    })
    findings = await cm.CronMisconfigPlugin().check(_Ctx(_CRED), _host())

    assert len(findings) == 1
    assert findings[0].severity is Severity.critical
    assert findings[0].title == "Root Cron Jobs Execute Scripts Writable by Non-Root Users"
    assert "/etc/cron.daily/backup.sh" in findings[0].evidence
    assert "world-writable" in findings[0].evidence


@pytest.mark.asyncio
async def test_correctly_permissioned_cron_entries_produce_nothing(monkeypatch):
    """Same script, root-owned and not group/world-writable: nothing to say."""
    _install(monkeypatch, {
        cm._PERM_CMD: "",
        cm._CONTENT_CMD: "",
        cm._DROPIN_CMD: "-rwxr-xr-x 1 0 0 512 Jan 6 2022 /etc/cron.daily/backup.sh",
    })
    findings = await cm.CronMisconfigPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_empty_output_produces_nothing(monkeypatch):
    _install(monkeypatch, {cm._PERM_CMD: "", cm._CONTENT_CMD: "", cm._DROPIN_CMD: ""})
    findings = await cm.CronMisconfigPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_missing_credentials_produces_nothing(monkeypatch):
    findings = await cm.CronMisconfigPlugin().check(_Ctx(None), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_unreachable_host_produces_nothing_not_an_exception(monkeypatch):
    _install(monkeypatch, {})
    findings = await cm.CronMisconfigPlugin().check(_Ctx(_CRED), _host())
    assert findings == []
