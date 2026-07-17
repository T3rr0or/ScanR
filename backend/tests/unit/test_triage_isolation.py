"""Regression: triage carryforward must be per-host.

ResultCollector._find_prior_triage previously matched prior findings by
plugin_id+port only (via user scans), so a false-positive marked on host A
bled onto the same plugin+port finding on host B. The fix keys the lookup on
the host IP. Two hosts in a new scan, same plugin+port: only the host whose IP
matches the triaged prior finding may inherit triage state.
"""
import pytest

from scanr.auth.password import hash_password
from scanr.core.plugin_base import FindingData, Severity
from scanr.core.result_collector import ResultCollector
from scanr.models import Finding, Host, Scan
from scanr.models.base import new_uuid
from scanr.models.user import User, UserRole


@pytest.mark.asyncio
async def test_triage_does_not_cross_hosts(db):
    user = User(id=new_uuid(), email="triage@example.com",
                hashed_password=hash_password("somepassword1"),
                role=UserRole.analyst, is_active=True)
    db.add(user)
    await db.flush()

    # Old scan: host 10.9.9.1 has a finding triaged as false positive.
    scan_old = Scan(id=new_uuid(), name="old", user_id=user.id)
    db.add(scan_old)
    await db.flush()
    host_old = Host(id=new_uuid(), scan_id=scan_old.id, ip="10.9.9.1")
    db.add(host_old)
    await db.flush()
    db.add(Finding(
        id=new_uuid(), scan_id=scan_old.id, host_id=host_old.id,
        plugin_id="ssl-cert", severity="low", title="Self-signed cert",
        port_number=443, false_positive=True,
    ))

    # New scan: same host rescanned (same IP) plus a DIFFERENT host.
    scan_new = Scan(id=new_uuid(), name="new", user_id=user.id)
    db.add(scan_new)
    await db.flush()
    host_same = Host(id=new_uuid(), scan_id=scan_new.id, ip="10.9.9.1")
    host_other = Host(id=new_uuid(), scan_id=scan_new.id, ip="10.9.9.2")
    db.add_all([host_same, host_other])
    await db.commit()

    collector = ResultCollector(scan_new.id, db, None, user_id=user.id)
    data = FindingData(plugin_id="ssl-cert", severity=Severity.low,
                       title="Self-signed cert", port_number=443)

    prior_same = await collector._find_prior_triage(host_same.id, data)
    assert prior_same is not None
    assert prior_same.false_positive is True

    prior_other = await collector._find_prior_triage(host_other.id, data)
    assert prior_other is None, "triage state must not leak across different hosts"

    # No host at all → no carryforward.
    assert await collector._find_prior_triage(None, data) is None
