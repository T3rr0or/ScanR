"""End-of-life operating system detection over authenticated SSH.

The plugin reads `/etc/os-release` and looks up the distro's vendor support
window. Severity is date-driven (`date.today()` inside the plugin), so these
tests freeze `os_eol.date` to a fixed value rather than depending on the
machine's real clock. Two things must never happen: guessing at a distro or
version that is not in the table, and reporting anything before credentials
are even available.
"""
from __future__ import annotations

from datetime import date
from types import SimpleNamespace

import pytest

from scanr.core.plugin_base import Severity
from scanr.plugins.authenticated import os_eol as oe

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
    """Stand in for the SSH session: return only the commands we were asked for."""
    async def fake(self, ip, port, cred, commands):
        return {c: outputs[c] for c in commands if c in outputs}
    monkeypatch.setattr(oe.OsEolPlugin, "_run_commands", fake)


def _freeze(monkeypatch, fixed: date):
    """Pin os_eol.date.today() without touching the real system clock."""
    class _Frozen(date):
        @classmethod
        def today(cls):
            return fixed
    monkeypatch.setattr(oe, "date", _Frozen)


def _os_release(distro_id: str, version_id: str, pretty: str | None = None) -> str:
    lines = [f"ID={distro_id}", f'VERSION_ID="{version_id}"']
    if pretty:
        lines.append(f'PRETTY_NAME="{pretty}"')
    return "\n".join(lines)


# ── plugin behaviour ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_long_eol_distro_is_reported_at_high(monkeypatch):
    """Ubuntu 18.04 (EOL 2023-05-31), 31 days past support: high, not critical
    (the critical threshold is ~3 years past)."""
    _freeze(monkeypatch, date(2023, 7, 1))
    _install(monkeypatch, {
        oe._OS_RELEASE_CMD: _os_release("ubuntu", "18.04", "Ubuntu 18.04.6 LTS"),
        oe._KERNEL_CMD: "5.4.0-42-generic",
    })
    findings = await oe.OsEolPlugin().check(_Ctx(_CRED), _host())

    assert len(findings) == 1
    assert findings[0].severity is Severity.high
    assert "18.04" in findings[0].title
    assert "2023-05-31" in findings[0].evidence


@pytest.mark.asyncio
async def test_current_distro_produces_nothing(monkeypatch):
    """Debian 12 (EOL 2028-06-30) is comfortably inside its support window."""
    _freeze(monkeypatch, date(2026, 1, 1))
    _install(monkeypatch, {
        oe._OS_RELEASE_CMD: _os_release("debian", "12", "Debian GNU/Linux 12 (bookworm)"),
        oe._KERNEL_CMD: "6.1.0-13-amd64",
    })
    findings = await oe.OsEolPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_unknown_distro_is_never_guessed_at(monkeypatch):
    """A distro absent from the table (or a version newer than it) must not
    be scored — guessing would be worse than staying silent."""
    _freeze(monkeypatch, date(2026, 1, 1))
    _install(monkeypatch, {
        oe._OS_RELEASE_CMD: _os_release("gentoo", "2.14"),
        oe._KERNEL_CMD: "6.1.0",
    })
    findings = await oe.OsEolPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_unparseable_os_release_produces_nothing(monkeypatch):
    _install(monkeypatch, {oe._OS_RELEASE_CMD: "this is not a key=value file at all"})
    findings = await oe.OsEolPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_missing_credentials_produces_nothing(monkeypatch):
    findings = await oe.OsEolPlugin().check(_Ctx(None), _host())
    assert findings == []


@pytest.mark.asyncio
async def test_unreachable_host_produces_nothing_not_an_exception(monkeypatch):
    """An SSH session that never connects returns {}, same as no findings."""
    _install(monkeypatch, {})
    findings = await oe.OsEolPlugin().check(_Ctx(_CRED), _host())
    assert findings == []


# ── support table ────────────────────────────────────────────────────────────

def test_support_table_dates_are_real_dates():
    assert oe.OS_EOL, "support table must not be empty"
    for distro, table in oe.OS_EOL.items():
        assert table, f"{distro} has no versions"
        for version_id, eol in table.items():
            assert isinstance(eol, date), f"{distro} {version_id}"
