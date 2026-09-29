"""Anonymous LDAP write detection.

Pins the result-code interpretation: a schema/naming rejection means the access
check passed (write permitted), insufficientAccessRights means it did not, and a
success means an object was created and must be flagged for removal.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scanr.plugins.services.ldap_anon_write import (
    LdapAnonWritePlugin,
    RESULT_INSUFFICIENT_ACCESS,
    RESULT_NO_SUCH_OBJECT,
    RESULT_OBJECT_CLASS_VIOLATION,
    RESULT_SUCCESS,
    WriteProbe,
    interpret,
)


def _port(number=389, state="open"):
    return SimpleNamespace(number=number, state=state)


def _host(ports, ip="192.0.2.130"):
    return SimpleNamespace(ip=ip, hostname=None, ports=ports)


def test_schema_violation_means_write_permitted():
    probe = WriteProbe(dn="CN=x,DC=y", result_code=RESULT_OBJECT_CLASS_VIOLATION)
    assert probe.permitted and not probe.created


def test_insufficient_access_means_denied():
    probe = WriteProbe(dn="CN=x,DC=y", result_code=RESULT_INSUFFICIENT_ACCESS)
    assert not probe.permitted and not probe.created


def test_success_means_object_created():
    probe = WriteProbe(dn="CN=x,DC=y", result_code=RESULT_SUCCESS)
    assert probe.created and not probe.permitted


def test_no_such_object_is_inconclusive():
    probe = WriteProbe(dn="CN=x,DC=y", result_code=RESULT_NO_SUCH_OBJECT)
    assert not probe.permitted and not probe.created


def test_interpret_is_human_readable():
    assert "objectClassViolation" in interpret(RESULT_OBJECT_CLASS_VIOLATION)
    assert "insufficientAccessRights" in interpret(RESULT_INSUFFICIENT_ACCESS)


@pytest.mark.asyncio
async def test_write_permitted_reported_high(monkeypatch):
    async def fake_probe(self, ip, port):
        return WriteProbe(dn="CN=p,DC=corp", result_code=RESULT_OBJECT_CLASS_VIOLATION)
    monkeypatch.setattr(LdapAnonWritePlugin, "_probe", fake_probe)
    findings = await LdapAnonWritePlugin().check(None, _host([_port()]))
    assert len(findings) == 1
    assert findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_object_created_reported_critical(monkeypatch):
    async def fake_probe(self, ip, port):
        return WriteProbe(dn="CN=p,DC=corp", result_code=RESULT_SUCCESS)
    monkeypatch.setattr(LdapAnonWritePlugin, "_probe", fake_probe)
    findings = await LdapAnonWritePlugin().check(None, _host([_port()]))
    assert findings[0].severity.value == "critical"
    assert "CN=p,DC=corp" in findings[0].evidence


@pytest.mark.asyncio
async def test_denied_write_is_silent(monkeypatch):
    async def fake_probe(self, ip, port):
        return WriteProbe(dn="CN=p,DC=corp", result_code=RESULT_INSUFFICIENT_ACCESS)
    monkeypatch.setattr(LdapAnonWritePlugin, "_probe", fake_probe)
    assert await LdapAnonWritePlugin().check(None, _host([_port()])) == []
