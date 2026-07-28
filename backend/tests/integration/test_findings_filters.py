"""Findings list filters.

These are server-side because they used to run in the browser over one page of
results, which meant a filter silently returned fewer rows than existed — five
validated findings among 303 displayed as four. A filter that under-reports
without saying so is worse than no filter, so the properties pinned here are
"the filter sees the whole table" and "a capped page admits it".
"""
import pytest
from sqlalchemy import delete as sa_delete, select


@pytest.fixture
async def many_findings(db):
    """A scan with more findings than fit one page, and a known distribution."""
    from scanr.models import Finding, Host, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    scan = Scan(id=new_uuid(), name="bulk", status=ScanStatus.completed,
                profile="standard", user_id=admin.id)
    db.add(scan)
    await db.flush()
    host = Host(id=new_uuid(), scan_id=scan.id, ip="198.51.100.7", status="up")
    db.add(host)
    await db.flush()

    rows = []
    for i in range(240):
        f = Finding(
            id=new_uuid(), scan_id=scan.id, host_id=host.id,
            plugin_id="web.http_headers" if i % 2 else "services.ftp_anon",
            severity="low", title=f"bulk finding {i}",
        )
        # The needles sit at the far end of the default ordering, so a
        # page-limited client would miss them.
        if i >= 235:
            f.validated = True
            f.validation_method = "browser-dialog"
            f.title = f"proven issue {i}"
        if i == 100:
            f.remediation_status = "accepted_risk"
        rows.append(f)
    db.add_all(rows)
    await db.commit()

    yield {"scan_id": scan.id, "total": 240, "validated": 5}

    await db.execute(sa_delete(Finding).where(Finding.scan_id == scan.id))
    await db.execute(sa_delete(Host).where(Host.scan_id == scan.id))
    await db.execute(sa_delete(Scan).where(Scan.id == scan.id))
    await db.commit()


async def get(client, headers, scan_id, **params):
    query = "&".join(f"{k}={v}" for k, v in params.items())
    r = await client.get(f"/api/v1/findings?scan_id={scan_id}&{query}", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_validated_filter_finds_all_of_them(client, auth_headers, many_findings):
    """The original bug: the needles are past the page the UI had loaded."""
    body = await get(client, auth_headers, many_findings["scan_id"],
                     validated="true", limit=500)
    assert len(body) == many_findings["validated"]
    assert all(f["validated"] for f in body)


@pytest.mark.asyncio
async def test_validated_false_is_the_complement(client, auth_headers, many_findings):
    body = await get(client, auth_headers, many_findings["scan_id"],
                     validated="false", limit=1000)
    assert len(body) == many_findings["total"] - many_findings["validated"]


@pytest.mark.asyncio
async def test_remediation_status_filter(client, auth_headers, many_findings):
    body = await get(client, auth_headers, many_findings["scan_id"],
                     remediation_status="accepted_risk", limit=500)
    assert len(body) == 1


@pytest.mark.asyncio
async def test_an_invalid_remediation_status_is_rejected(client, auth_headers, many_findings):
    r = await client.get(
        f"/api/v1/findings?scan_id={many_findings['scan_id']}&remediation_status=bogus",
        headers=auth_headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_search_matches_title_host_and_plugin(client, auth_headers, many_findings):
    sid = many_findings["scan_id"]
    assert len(await get(client, auth_headers, sid, q="proven", limit=500)) == 5
    assert len(await get(client, auth_headers, sid, q="198.51.100.7", limit=1000)) == 240
    assert len(await get(client, auth_headers, sid, q="ftp_anon", limit=1000)) == 120
    assert await get(client, auth_headers, sid, q="nothingmatchesthis", limit=500) == []


@pytest.mark.asyncio
async def test_filters_combine(client, auth_headers, many_findings):
    body = await get(client, auth_headers, many_findings["scan_id"],
                     validated="true", q="proven", limit=500)
    assert len(body) == 5


@pytest.mark.asyncio
async def test_the_limit_allows_one_row_past_a_500_row_page(client, auth_headers, many_findings):
    """The UI shows 500 rows and needs to know whether a 501st exists.

    Inferring "there is more" from a full page is wrong at exactly the page size:
    with precisely 500 matches it claimed more existed. So the cap has to permit
    501, and this pins that it does.
    """
    r = await client.get(
        f"/api/v1/findings?scan_id={many_findings['scan_id']}&limit=501", headers=auth_headers
    )
    assert r.status_code == 200, r.text
    # And the ceiling is still a ceiling.
    over = await client.get(
        f"/api/v1/findings?scan_id={many_findings['scan_id']}&limit=100000", headers=auth_headers
    )
    assert over.status_code == 422


@pytest.mark.asyncio
async def test_csv_export_honours_the_same_filters(client, auth_headers, many_findings):
    """Otherwise the download is a differently-filtered list than the one on screen."""
    r = await client.get(
        f"/api/v1/findings/export?scan_id={many_findings['scan_id']}&validated=true",
        headers=auth_headers,
    )
    assert r.status_code == 200, r.text
    lines = [ln for ln in r.text.strip().splitlines() if ln]
    assert len(lines) == 1 + many_findings["validated"], "header plus the validated rows"
    assert "validated" in lines[0]
