"""Attack-path endpoint: ownership, triage awareness, and the inference toggle."""
import pytest
from sqlalchemy import delete as sa_delete


@pytest.fixture
async def graph_scan(db):
    """A scan with a full break-in → credential → DC → domain chain."""
    from scanr.models import Finding, Host, Port, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User
    from sqlalchemy import select

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    scan = Scan(id=new_uuid(), name="graph-scan", status=ScanStatus.completed,
                profile="standard", user_id=admin.id)
    db.add(scan)
    await db.flush()

    web = Host(id=new_uuid(), scan_id=scan.id, ip="192.0.2.10", hostname="www01", status="up")
    dc = Host(id=new_uuid(), scan_id=scan.id, ip="192.0.2.5", hostname="dc01", status="up")
    db.add_all([web, dc])
    await db.flush()
    db.add_all([
        Port(id=new_uuid(), host_id=web.id, number=6379, protocol="tcp", state="open"),
        Port(id=new_uuid(), host_id=dc.id, number=445, protocol="tcp", state="open"),
        # A filtered port must not count as an auth service.
        Port(id=new_uuid(), host_id=dc.id, number=3389, protocol="tcp", state="filtered"),
    ])

    def f(plugin_id, severity, host, **kw):
        return Finding(id=new_uuid(), scan_id=scan.id, host_id=host.id,
                       plugin_id=plugin_id, severity=severity,
                       title=kw.pop("title", plugin_id), **kw)

    fp = f("services.redis_unauth", "critical", web, title="dismissed dupe")
    fp.false_positive = True
    db.add_all([
        f("services.redis_unauth", "critical", web),
        f("web.sensitive_files", "high", web),
        # A demonstrated authentication onto the DC, so the default
        # (evidence-only) graph has a real route and not just a hypothesis.
        f("services.admin_share_access", "high", dc),
        f("services.dcsync_check", "critical", dc, evidence="domain: corp.example.com"),
        f("web.http_headers", "low", web),   # hardening: must not create an edge
        fp,
    ])
    await db.commit()

    yield {"scan_id": scan.id, "web_id": web.id, "dc_id": dc.id}

    await db.execute(sa_delete(Finding).where(Finding.scan_id == scan.id))
    for h in (web, dc):
        await db.execute(sa_delete(Port).where(Port.host_id == h.id))
    await db.execute(sa_delete(Host).where(Host.scan_id == scan.id))
    await db.execute(sa_delete(Scan).where(Scan.id == scan.id))
    await db.commit()


@pytest.mark.asyncio
async def test_returns_a_ranked_path_to_the_domain(client, auth_headers, graph_scan):
    r = await client.get(f"/api/v1/scans/{graph_scan['scan_id']}/attack-paths",
                         headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["summary"]["host_count"] == 2
    assert body["paths"], "expected at least one route"
    path = body["paths"][0]
    assert path["severity"] == "critical"
    assert "corp.example.com" in path["objective"]
    assert path["steps"][0]["kind"] == "foothold"
    assert path["steps"][-1]["kind"] == "domain_compromise"


@pytest.mark.asyncio
async def test_every_non_inferred_edge_cites_a_finding(client, auth_headers, graph_scan):
    r = await client.get(f"/api/v1/scans/{graph_scan['scan_id']}/attack-paths",
                         headers=auth_headers)
    for edge in r.json()["edges"]:
        if not edge["inferred"] and edge["target"] != "cred:supplied":
            assert edge["finding_ids"], f"unjustified edge: {edge['label']}"


@pytest.mark.asyncio
async def test_hardening_findings_produce_no_edges(client, auth_headers, graph_scan):
    r = await client.get(f"/api/v1/scans/{graph_scan['scan_id']}/attack-paths",
                         headers=auth_headers)
    labels = " ".join(e["label"] for e in r.json()["edges"]).lower()
    assert "header" not in labels


@pytest.mark.asyncio
async def test_false_positives_are_excluded(client, auth_headers, graph_scan, db):
    """A path built on a dismissed finding is worse than no path."""
    from scanr.models import Finding
    from sqlalchemy import select

    dismissed = (await db.execute(
        select(Finding.id).where(Finding.title == "dismissed dupe")
    )).scalar_one()

    r = await client.get(f"/api/v1/scans/{graph_scan['scan_id']}/attack-paths",
                         headers=auth_headers)
    cited = {fid for e in r.json()["edges"] for fid in e["finding_ids"]}
    assert dismissed not in cited


@pytest.mark.asyncio
async def test_inference_toggle_changes_the_graph(client, auth_headers, graph_scan):
    sid = graph_scan["scan_id"]
    loose = (await client.get(f"/api/v1/scans/{sid}/attack-paths?include_inferred=true",
                              headers=auth_headers)).json()
    strict = (await client.get(f"/api/v1/scans/{sid}/attack-paths",
                               headers=auth_headers)).json()

    assert any(e["inferred"] for e in loose["edges"]), "expected a reuse hypothesis"
    assert not any(e["inferred"] for e in strict["edges"]), (
        "evidence-only is the default: inference costs 92% of the edges on a real "
        "scan and never appears in a ranked path"
    )
    assert len(strict["edges"]) < len(loose["edges"])


@pytest.mark.asyncio
async def test_filtered_ports_do_not_count_as_auth_services(client, auth_headers, graph_scan):
    r = await client.get(f"/api/v1/scans/{graph_scan['scan_id']}/attack-paths",
                         headers=auth_headers)
    reuse = [e for e in r.json()["edges"] if e["kind"] == "credential_reuse"]
    for e in reuse:
        assert "RDP" not in e["label"], "3389 is filtered, not open"


@pytest.mark.asyncio
async def test_max_paths_is_honoured(client, auth_headers, graph_scan):
    r = await client.get(f"/api/v1/scans/{graph_scan['scan_id']}/attack-paths?max_paths=1",
                         headers=auth_headers)
    assert len(r.json()["paths"]) <= 1


@pytest.mark.asyncio
async def test_another_users_scan_is_not_visible(client, auth_headers, graph_scan):
    """Ownership, not just authentication."""
    created = await client.post("/api/v1/users", headers=auth_headers, json={
        "email": "other-graph@scanr.local", "password": "othergraph123", "role": "analyst",
    })
    assert created.status_code == 201, created.text
    uid = created.json()["id"]
    login = await client.post("/api/v1/auth/login", json={
        "email": "other-graph@scanr.local", "password": "othergraph123",
    })
    other = {"Authorization": f"Bearer {login.json()['access_token']}"}

    r = await client.get(f"/api/v1/scans/{graph_scan['scan_id']}/attack-paths", headers=other)
    assert r.status_code == 404, r.text

    await client.delete(f"/api/v1/users/{uid}", headers=auth_headers)


@pytest.mark.asyncio
async def test_unknown_scan_is_404(client, auth_headers):
    r = await client.get("/api/v1/scans/does-not-exist/attack-paths", headers=auth_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_empty_scan_returns_an_empty_graph(client, auth_headers):
    created = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "empty-graph", "targets": ["192.0.2.77"],
    })
    sid = created.json()["id"]
    r = await client.get(f"/api/v1/scans/{sid}/attack-paths", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["paths"] == []
    assert body["summary"]["worst_severity"] is None
    assert len(body["nodes"]) == 1  # just the entry node


@pytest.mark.asyncio
async def test_an_inference_only_scan_says_so_rather_than_looking_empty(
    client, auth_headers, db
):
    """With inference off by default, a scan whose only route is a hypothesis
    returns no paths — which reads as "nothing here" to anyone who does not know
    the default flipped. The response has to distinguish the two cases."""
    from scanr.models import Finding, Host, Port, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User
    from sqlalchemy import select

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    scan = Scan(id=new_uuid(), name="inference-only", status=ScanStatus.completed,
                profile="standard", user_id=admin.id)
    db.add(scan)
    await db.flush()
    web = Host(id=new_uuid(), scan_id=scan.id, ip="192.0.2.20", status="up")
    dc = Host(id=new_uuid(), scan_id=scan.id, ip="192.0.2.21", status="up")
    db.add_all([web, dc])
    await db.flush()
    db.add_all([
        Port(id=new_uuid(), host_id=web.id, number=6379, protocol="tcp", state="open"),
        Port(id=new_uuid(), host_id=dc.id, number=445, protocol="tcp", state="open"),
    ])

    def f(plugin_id, severity, host, **kw):
        return Finding(id=new_uuid(), scan_id=scan.id, host_id=host.id,
                       plugin_id=plugin_id, severity=severity, title=plugin_id, **kw)

    # No demonstrated route onto the DC — only reuse could bridge the gap.
    db.add_all([
        f("services.redis_unauth", "critical", web),
        f("web.sensitive_files", "high", web),
        f("services.dcsync_check", "critical", dc),
    ])
    await db.commit()
    try:
        body = (await client.get(f"/api/v1/scans/{scan.id}/attack-paths",
                                 headers=auth_headers)).json()
        assert body["paths"] == []
        assert body["inferred_paths_available"] >= 1, (
            "the UI cannot tell 'nothing connects' from 'nothing proven' without this"
        )

        # And with inference on, those routes actually appear.
        loose = (await client.get(
            f"/api/v1/scans/{scan.id}/attack-paths?include_inferred=true",
            headers=auth_headers,
        )).json()
        assert len(loose["paths"]) == body["inferred_paths_available"]
        assert loose["inferred_paths_available"] is None, "only set when there was nothing to show"
    finally:
        await db.execute(sa_delete(Finding).where(Finding.scan_id == scan.id))
        for h in (web, dc):
            await db.execute(sa_delete(Port).where(Port.host_id == h.id))
        await db.execute(sa_delete(Host).where(Host.scan_id == scan.id))
        await db.execute(sa_delete(Scan).where(Scan.id == scan.id))
        await db.commit()


@pytest.mark.asyncio
async def test_nothing_connecting_at_all_is_reported_as_zero_not_null(
    client, auth_headers, db
):
    """Zero and null mean different things: zero is "checked, nothing there"."""
    from scanr.models import Finding, Host, Scan, ScanStatus
    from scanr.models.base import new_uuid
    from scanr.models.user import User
    from sqlalchemy import select

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    scan = Scan(id=new_uuid(), name="disconnected", status=ScanStatus.completed,
                profile="standard", user_id=admin.id)
    db.add(scan)
    await db.flush()
    h = Host(id=new_uuid(), scan_id=scan.id, ip="192.0.2.30", status="up")
    db.add(h)
    await db.flush()
    db.add(Finding(id=new_uuid(), scan_id=scan.id, host_id=h.id,
                   plugin_id="web.http_headers", severity="low", title="hardening only"))
    await db.commit()
    try:
        body = (await client.get(f"/api/v1/scans/{scan.id}/attack-paths",
                                 headers=auth_headers)).json()
        assert body["paths"] == []
        assert body["inferred_paths_available"] == 0
    finally:
        await db.execute(sa_delete(Finding).where(Finding.scan_id == scan.id))
        await db.execute(sa_delete(Host).where(Host.scan_id == scan.id))
        await db.execute(sa_delete(Scan).where(Scan.id == scan.id))
        await db.commit()
