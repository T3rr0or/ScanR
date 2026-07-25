"""The scope handed to the egress relay must be addresses the relay can enforce.

The relay allowlist is L3: a hostname is not an egress rule, because what it
resolves to can change. A domain-target scan would therefore hand over an
unusable scope and fail closed with no explanation — so discovered host IPs are
included alongside IP/CIDR targets.
"""
import pytest
from sqlalchemy import delete as sa_delete


@pytest.fixture
async def scan_with(db):
    """Build a scan with given targets + discovered hosts; yield a DbAgentContext."""
    from scanr.models import Host, Scan, ScanStatus, Target
    from scanr.models.base import new_uuid
    from scanr.models.user import User
    from sqlalchemy import select

    created: list[str] = []

    async def _make(targets: list[str], hosts: list[str]):
        admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
        scan = Scan(
            id=new_uuid(), name="scope-scan", status=ScanStatus.completed,
            profile="standard", user_id=admin.id,
        )
        db.add(scan)
        await db.flush()
        for t in targets:
            db.add(Target(id=new_uuid(), scan_id=scan.id, value=t, type="ip"))
        for ip in hosts:
            db.add(Host(id=new_uuid(), scan_id=scan.id, ip=ip, status="up"))
        await db.commit()
        created.append(scan.id)

        from scanr.ai.agent.db_context import DbAgentContext
        from scanr.ai.agent.policy import AgentPolicy, Budget
        from scanr.core.scan_logger import ScanLogger
        from scanr.config import get_settings

        return DbAgentContext(
            scan_id=scan.id,
            db=db,
            policy=AgentPolicy(),
            budget=Budget(),
            denylist=get_settings().scan_denylist,
            logger=ScanLogger(scan.id),
        )

    yield _make

    for sid in created:
        await db.execute(sa_delete(Host).where(Host.scan_id == sid))
        await db.execute(sa_delete(Target).where(Target.scan_id == sid))
        await db.execute(sa_delete(Scan).where(Scan.id == sid))
    await db.commit()


@pytest.mark.asyncio
async def test_ip_and_cidr_targets_are_kept(scan_with):
    ctx = await scan_with(["192.0.2.10", "198.51.100.0/24"], [])
    assert set(await ctx._scope_cidrs()) == {"192.0.2.10", "198.51.100.0/24"}


@pytest.mark.asyncio
async def test_hostname_targets_are_replaced_by_discovered_ips(scan_with):
    """The domain-scan case: the relay cannot enforce 'example.com', but it can
    enforce the addresses discovery actually found."""
    ctx = await scan_with(["example.com"], ["198.51.100.7", "198.51.100.8"])
    scope = await ctx._scope_cidrs()
    assert "example.com" not in scope
    assert set(scope) == {"198.51.100.7", "198.51.100.8"}


@pytest.mark.asyncio
async def test_targets_and_hosts_are_unioned_not_either_or(scan_with):
    ctx = await scan_with(["192.0.2.0/24"], ["198.51.100.7"])
    assert set(await ctx._scope_cidrs()) == {"192.0.2.0/24", "198.51.100.7"}


@pytest.mark.asyncio
async def test_legacy_numeric_target_is_normalized(scan_with):
    ctx = await scan_with(["3221225994"], [])  # 192.0.2.10
    assert await ctx._scope_cidrs() == ["192.0.2.10"]


@pytest.mark.asyncio
async def test_forbidden_addresses_never_enter_the_scope(scan_with):
    """Even if such rows existed, the allowlist must not authorize them."""
    ctx = await scan_with(["192.0.2.10"], ["127.0.0.1", "169.254.169.254", "::1"])
    assert await ctx._scope_cidrs() == ["192.0.2.10"]


@pytest.mark.asyncio
async def test_hostname_only_scan_with_no_hosts_yields_empty_scope(scan_with):
    """Empty scope is the fail-closed signal: run_command refuses rather than
    starting a relay that would allow nothing."""
    ctx = await scan_with(["example.com"], [])
    assert await ctx._scope_cidrs() == []


@pytest.mark.asyncio
async def test_scope_is_parseable_by_the_relay(scan_with):
    """End-to-end contract: whatever _scope_cidrs emits, the relay must accept."""
    from scanr.sandbox.egress_relay import parse_allowlist

    ctx = await scan_with(["192.0.2.0/24", "3221225994"], ["198.51.100.7"])
    scope = await ctx._scope_cidrs()
    nets = parse_allowlist(",".join(scope))
    assert len(nets) == len(scope), f"relay dropped entries from {scope}"
