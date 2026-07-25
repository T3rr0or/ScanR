"""Marking a finding as reproduced.

`validated` is only useful if it is hard to earn, so the properties worth pinning
are about what does NOT set it: a canary the agent chose, a payload that was
merely reflected, a page that would not load. Chromium is stubbed — the browser
itself is not what these are about, and core/validation.py already covers the
verdict rules.
"""
import pytest
from sqlalchemy import delete as sa_delete, select


@pytest.fixture
async def scan_ctx(db):
    """A completed scan with one discovered host and one finding on it."""
    from scanr.config import get_settings
    from scanr.ai.agent.db_context import DbAgentContext
    from scanr.ai.agent.policy import AgentPolicy, Budget
    from scanr.core.scan_logger import ScanLogger
    from scanr.models import Finding, Host, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    scan = Scan(id=new_uuid(), name="validate-scan", status=ScanStatus.completed,
                profile="standard", user_id=admin.id)
    db.add(scan)
    await db.flush()
    host = Host(id=new_uuid(), scan_id=scan.id, ip="192.0.2.10", status="up")
    db.add(host)
    await db.flush()
    finding = Finding(
        id=new_uuid(), scan_id=scan.id, host_id=host.id, plugin_id="web.xss",
        severity="high", title="Reflected parameter", port_number=80, protocol="tcp",
    )
    db.add(finding)
    await db.commit()

    ctx = DbAgentContext(
        scan_id=scan.id, db=db, policy=AgentPolicy(), budget=Budget(),
        denylist=get_settings().scan_denylist, logger=ScanLogger(scan.id),
    )
    yield ctx, finding

    await db.execute(sa_delete(Finding).where(Finding.scan_id == scan.id))
    await db.execute(sa_delete(Host).where(Host.scan_id == scan.id))
    await db.execute(sa_delete(Scan).where(Scan.id == scan.id))
    await db.commit()


def stub_browser(monkeypatch, build):
    """Replace Chromium with a function that reports what `build(url, canary)` says."""
    seen = {}

    async def fake_observe(url, canary, **kw):
        seen["url"] = url
        seen["canary"] = canary
        return build(url, canary)

    monkeypatch.setattr("scanr.core.browser.observe_url", fake_observe)
    return seen


def executed(url, canary):
    return {"url": url, "status": 200, "title": "x", "dialogs": [{"type": "alert", "message": canary}],
            "console": [], "page_errors": [], "canary_in_dom": True, "error": None}


def reflected_only(url, canary):
    return {"url": url, "status": 200, "title": "x", "dialogs": [], "console": [],
            "page_errors": [], "canary_in_dom": True, "error": None}


def unreachable(url, canary):
    return {"url": url, "status": None, "title": None, "dialogs": [], "console": [],
            "page_errors": [], "canary_in_dom": False, "error": "net::ERR_CONNECTION_REFUSED"}


@pytest.mark.asyncio
async def test_execution_marks_the_finding_validated(scan_ctx, db, monkeypatch):
    ctx, finding = scan_ctx
    stub_browser(monkeypatch, executed)

    out = await ctx.validate_in_browser(
        "http://192.0.2.10/s?q=<script>alert('{CANARY}')</script>", finding.id
    )
    assert out["verdict"] == "proved"
    assert out["validated_finding"] is True

    await db.refresh(finding)
    assert finding.validated is True
    assert finding.validation_method == "browser-dialog"
    assert "alert()" in finding.validation_evidence
    assert finding.validated_at is not None


@pytest.mark.asyncio
async def test_the_canary_is_ours_not_the_agents(scan_ctx, monkeypatch):
    """The agent writes the payload but not the marker it is judged against —
    otherwise it could 'prove' anything by naming a string already on the page."""
    ctx, finding = scan_ctx
    seen = stub_browser(monkeypatch, executed)

    await ctx.validate_in_browser("http://192.0.2.10/s?q={CANARY}", finding.id)
    canary = seen["canary"]
    assert canary.startswith("scanr") and len(canary) == 21
    assert "{CANARY}" not in seen["url"]
    assert canary in seen["url"]

    # and a second attempt gets a different token
    await ctx.validate_in_browser("http://192.0.2.10/s?q={CANARY}", finding.id)
    assert seen["canary"] != canary


@pytest.mark.asyncio
async def test_a_url_without_the_placeholder_is_rejected(scan_ctx, monkeypatch):
    ctx, finding = scan_ctx
    stub_browser(monkeypatch, executed)
    with pytest.raises(ValueError, match="CANARY"):
        await ctx.validate_in_browser("http://192.0.2.10/s?q=alert(1)", finding.id)


@pytest.mark.asyncio
async def test_reflection_does_not_mark_the_finding(scan_ctx, db, monkeypatch):
    ctx, finding = scan_ctx
    stub_browser(monkeypatch, reflected_only)

    out = await ctx.validate_in_browser("http://192.0.2.10/s?q={CANARY}", finding.id)
    assert out["verdict"] == "reflected"
    assert out["validated_finding"] is False

    await db.refresh(finding)
    assert finding.validated is False
    assert finding.validation_method is None


@pytest.mark.asyncio
async def test_an_unreachable_page_does_not_mark_the_finding(scan_ctx, db, monkeypatch):
    ctx, finding = scan_ctx
    stub_browser(monkeypatch, unreachable)

    out = await ctx.validate_in_browser("http://192.0.2.10/s?q={CANARY}", finding.id)
    assert out["verdict"] == "inconclusive"

    await db.refresh(finding)
    assert finding.validated is False


@pytest.mark.asyncio
async def test_a_later_failure_never_clears_an_earlier_proof(scan_ctx, db, monkeypatch):
    """Whether the issue is still there is the retest feature's question. Proof
    that it was reproducible does not expire because a request timed out."""
    ctx, finding = scan_ctx
    stub_browser(monkeypatch, executed)
    await ctx.validate_in_browser("http://192.0.2.10/s?q={CANARY}", finding.id)

    stub_browser(monkeypatch, unreachable)
    await ctx.validate_in_browser("http://192.0.2.10/s?q={CANARY}", finding.id)

    await db.refresh(finding)
    assert finding.validated is True


@pytest.mark.asyncio
async def test_proof_clears_a_false_positive_mark(scan_ctx, db, monkeypatch):
    """Someone dismissed it; the browser then ran the payload. The machine
    evidence wins — leaving it dismissed would hide a demonstrated issue."""
    ctx, finding = scan_ctx
    finding.false_positive = True
    await db.commit()

    stub_browser(monkeypatch, executed)
    await ctx.validate_in_browser("http://192.0.2.10/s?q={CANARY}", finding.id)

    await db.refresh(finding)
    assert finding.validated is True
    assert finding.false_positive is False


@pytest.mark.asyncio
async def test_a_finding_from_another_scan_is_not_touched(scan_ctx, db, monkeypatch):
    """The context is scoped to one scan; an id from elsewhere must not be
    writable through it."""
    from scanr.models import Finding, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    ctx, finding = scan_ctx
    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    other_scan = Scan(id=new_uuid(), name="other", status=ScanStatus.completed,
                      profile="standard", user_id=admin.id)
    db.add(other_scan)
    await db.flush()
    other = Finding(id=new_uuid(), scan_id=other_scan.id, plugin_id="web.xss",
                    severity="high", title="Someone else's finding")
    db.add(other)
    await db.commit()
    try:
        stub_browser(monkeypatch, executed)
        out = await ctx.validate_in_browser("http://192.0.2.10/s?q={CANARY}", other.id)
        assert out["verdict"] == "proved", "the attempt still ran"
        assert out["validated_finding"] is False
        assert "not part of this scan" in out["note"]

        await db.refresh(other)
        assert other.validated is False
    finally:
        await db.execute(sa_delete(Finding).where(Finding.id == other.id))
        await db.execute(sa_delete(Scan).where(Scan.id == other_scan.id))
        await db.commit()


@pytest.mark.asyncio
async def test_validation_without_a_finding_id_just_reports(scan_ctx, monkeypatch):
    """Useful for probing before there is a finding to attach the proof to."""
    ctx, _ = scan_ctx
    stub_browser(monkeypatch, executed)
    out = await ctx.validate_in_browser("http://192.0.2.10/s?q={CANARY}")
    assert out["verdict"] == "proved"
    assert out["validated_finding"] is False
