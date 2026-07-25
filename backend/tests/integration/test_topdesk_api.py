"""TOPdesk endpoints: admin-gated config, secret handling, and ticket dedup."""
import httpx
import pytest
from sqlalchemy import delete as sa_delete, select


@pytest.fixture(autouse=True)
async def clean_topdesk(db):
    from scanr.integrations import topdesk

    await topdesk.clear_config(db)
    yield
    await topdesk.clear_config(db)


@pytest.fixture
async def finding_fixture(db):
    from scanr.models import Finding, Host, Scan, ScanStatus, TicketLink
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    admin = (await db.execute(select(User).where(User.email == "admin@scanr.local"))).scalar_one()
    scan = Scan(id=new_uuid(), name="td-scan", status=ScanStatus.completed,
                profile="standard", user_id=admin.id)
    db.add(scan)
    await db.flush()
    host = Host(id=new_uuid(), scan_id=scan.id, ip="192.0.2.50", status="up")
    db.add(host)
    await db.flush()
    f = Finding(id=new_uuid(), scan_id=scan.id, host_id=host.id,
                plugin_id="services.ftp_anon", severity="high",
                title="Anonymous FTP login allowed", port_number=21)
    db.add(f)
    await db.commit()

    yield {"finding_id": f.id, "scan_id": scan.id}

    await db.execute(sa_delete(TicketLink).where(TicketLink.finding_id == f.id))
    await db.execute(sa_delete(Finding).where(Finding.scan_id == scan.id))
    await db.execute(sa_delete(Host).where(Host.scan_id == scan.id))
    await db.execute(sa_delete(Scan).where(Scan.id == scan.id))
    await db.commit()


async def _configure(db, defaults=None):
    from scanr.integrations import topdesk

    await topdesk.save_config(db, url="https://example.topdesk.net", username="scanr",
                              password="app-password", defaults=defaults or {})


# ── configuration ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_config_requires_admin(client, auth_headers):
    created = await client.post("/api/v1/users", headers=auth_headers, json={
        "email": "td-analyst@scanr.local", "password": "tdanalyst123", "role": "analyst",
    })
    uid = created.json()["id"]
    login = await client.post("/api/v1/auth/login", json={
        "email": "td-analyst@scanr.local", "password": "tdanalyst123"})
    analyst = {"Authorization": f"Bearer {login.json()['access_token']}"}

    r = await client.put("/api/v1/integrations/topdesk", headers=analyst, json={
        "url": "https://example.topdesk.net", "username": "x", "password": "y"})
    assert r.status_code == 403, r.text
    assert (await client.get("/api/v1/integrations/topdesk", headers=analyst)).status_code == 403

    await client.delete(f"/api/v1/users/{uid}", headers=auth_headers)


@pytest.mark.asyncio
async def test_password_is_never_returned(client, auth_headers):
    r = await client.put("/api/v1/integrations/topdesk", headers=auth_headers, json={
        "url": "https://example.topdesk.net", "username": "scanr", "password": "s3cr3t"})
    assert r.status_code == 204, r.text

    status = (await client.get("/api/v1/integrations/topdesk", headers=auth_headers)).json()
    assert status["configured"] is True
    assert status["has_password"] is True
    assert "s3cr3t" not in str(status)
    assert "password" not in {k for k in status if k != "has_password"}


@pytest.mark.asyncio
async def test_password_is_encrypted_at_rest(client, auth_headers, db):
    await client.put("/api/v1/integrations/topdesk", headers=auth_headers, json={
        "url": "https://example.topdesk.net", "username": "scanr", "password": "s3cr3t"})

    from scanr.models import AppSetting

    stored = (await db.execute(
        select(AppSetting.value).where(AppSetting.key == "integration.topdesk.password")
    )).scalar_one()
    assert "s3cr3t" not in stored
    assert stored.startswith("gAAAAA"), "expected Fernet ciphertext"


@pytest.mark.asyncio
async def test_url_pointing_at_infrastructure_is_refused(client, auth_headers):
    r = await client.put("/api/v1/integrations/topdesk", headers=auth_headers, json={
        "url": "http://169.254.169.254", "username": "scanr", "password": "x"})
    assert r.status_code == 400, r.text
    assert "loopback" in r.json()["detail"] or "infrastructure" in r.json()["detail"]


@pytest.mark.asyncio
async def test_first_configuration_requires_a_password(client, auth_headers):
    r = await client.put("/api/v1/integrations/topdesk", headers=auth_headers, json={
        "url": "https://example.topdesk.net", "username": "scanr"})
    assert r.status_code == 400, r.text
    assert "required the first time" in r.json()["detail"]


@pytest.mark.asyncio
async def test_url_can_be_edited_without_resupplying_the_password(client, auth_headers, db):
    await _configure(db)
    r = await client.put("/api/v1/integrations/topdesk", headers=auth_headers, json={
        "url": "https://moved.topdesk.net", "username": "scanr"})
    assert r.status_code == 204, r.text

    from scanr.integrations import topdesk
    config = await topdesk.load_config(db)
    assert config.url == "https://moved.topdesk.net"
    assert config.password == "app-password", "the stored secret must survive"


@pytest.mark.asyncio
async def test_delete_clears_the_configuration(client, auth_headers, db):
    await _configure(db)
    assert (await client.delete("/api/v1/integrations/topdesk",
                                headers=auth_headers)).status_code == 204
    status = (await client.get("/api/v1/integrations/topdesk", headers=auth_headers)).json()
    assert status["configured"] is False


@pytest.mark.asyncio
async def test_test_endpoint_without_configuration_is_a_clear_400(client, auth_headers):
    r = await client.post("/api/v1/integrations/topdesk/test", headers=auth_headers)
    assert r.status_code == 400
    assert "not configured" in r.json()["detail"]


# ── ticket creation ──────────────────────────────────────────────────────────

def _mock(handler):
    """Patch the client the orchestration builds so no network is touched."""
    from scanr.integrations import topdesk

    original = topdesk.TopdeskClient

    def factory(config, *a, **kw):
        return original(config, transport=httpx.MockTransport(handler))

    return factory


@pytest.mark.asyncio
async def test_creates_a_ticket_and_links_it(client, auth_headers, db, finding_fixture, monkeypatch):
    from scanr.integrations import topdesk

    await _configure(db, {"category": "Security"})
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(201, json={"id": "inc-1", "number": "I 2403 001",
                                         "processingStatus": {"name": "Registered"}})

    monkeypatch.setattr(topdesk, "TopdeskClient", _mock(handler))

    r = await client.post(
        f"/api/v1/integrations/topdesk/findings/{finding_fixture['finding_id']}/ticket",
        headers=auth_headers)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["created"] is True
    assert body["external_key"] == "I 2403 001"
    assert body["external_status"] == "Registered"
    assert body["url"].startswith("https://example.topdesk.net/")
    assert calls == ["GET", "POST"], "must search before creating"


@pytest.mark.asyncio
async def test_second_request_reuses_the_link_without_calling_topdesk(
    client, auth_headers, db, finding_fixture, monkeypatch
):
    """Pressing the button twice must not open two incidents."""
    from scanr.integrations import topdesk

    await _configure(db)
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(201, json={"id": "inc-1", "number": "I 1"})

    monkeypatch.setattr(topdesk, "TopdeskClient", _mock(handler))
    fid = finding_fixture["finding_id"]
    url = f"/api/v1/integrations/topdesk/findings/{fid}/ticket"

    first = await client.post(url, headers=auth_headers)
    assert first.json()["created"] is True
    before = len(calls)

    second = await client.post(url, headers=auth_headers)
    assert second.status_code == 201
    assert second.json()["created"] is False, "must report adoption, not a new ticket"
    assert second.json()["external_id"] == first.json()["external_id"]
    assert len(calls) == before, "the local link should short-circuit the round trip"


@pytest.mark.asyncio
async def test_existing_incident_is_adopted_when_the_local_link_is_missing(
    client, auth_headers, db, finding_fixture, monkeypatch
):
    """Covers a restored database, or a ticket opened by another ScanR instance:
    the external number is what makes this recoverable."""
    from scanr.integrations import topdesk

    await _configure(db)
    posted = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=[{"id": "inc-existing", "number": "I 9"}])
        posted.append(request)
        return httpx.Response(201, json={"id": "should-not-happen"})

    monkeypatch.setattr(topdesk, "TopdeskClient", _mock(handler))

    r = await client.post(
        f"/api/v1/integrations/topdesk/findings/{finding_fixture['finding_id']}/ticket",
        headers=auth_headers)
    assert r.status_code == 201, r.text
    assert r.json()["created"] is False
    assert r.json()["external_id"] == "inc-existing"
    assert posted == [], "must not create when one already exists"


@pytest.mark.asyncio
async def test_ticket_creation_needs_triage_scope(client, auth_headers, db, finding_fixture):
    await _configure(db)
    created = await client.post("/api/v1/users", headers=auth_headers, json={
        "email": "td-viewer@scanr.local", "password": "tdviewer123", "role": "viewer"})
    uid = created.json()["id"]
    login = await client.post("/api/v1/auth/login", json={
        "email": "td-viewer@scanr.local", "password": "tdviewer123"})
    viewer = {"Authorization": f"Bearer {login.json()['access_token']}"}

    r = await client.post(
        f"/api/v1/integrations/topdesk/findings/{finding_fixture['finding_id']}/ticket",
        headers=viewer)
    assert r.status_code == 403, r.text

    await client.delete(f"/api/v1/users/{uid}", headers=auth_headers)


@pytest.mark.asyncio
async def test_unconfigured_integration_gives_a_clear_error(
    client, auth_headers, finding_fixture
):
    r = await client.post(
        f"/api/v1/integrations/topdesk/findings/{finding_fixture['finding_id']}/ticket",
        headers=auth_headers)
    assert r.status_code == 502, r.text
    assert "not configured" in r.json()["detail"]


@pytest.mark.asyncio
async def test_topdesk_failure_is_surfaced_not_swallowed(
    client, auth_headers, db, finding_fixture, monkeypatch
):
    from scanr.integrations import topdesk

    await _configure(db)
    monkeypatch.setattr(topdesk, "TopdeskClient",
                        _mock(lambda r: httpx.Response(401, text="nope")))

    r = await client.post(
        f"/api/v1/integrations/topdesk/findings/{finding_fixture['finding_id']}/ticket",
        headers=auth_headers)
    assert r.status_code == 502
    assert "credentials" in r.json()["detail"]


@pytest.mark.asyncio
async def test_another_users_finding_is_not_ticketable(
    client, auth_headers, db, finding_fixture, monkeypatch
):
    from scanr.integrations import topdesk

    await _configure(db)
    monkeypatch.setattr(topdesk, "TopdeskClient",
                        _mock(lambda r: httpx.Response(200, json=[])))

    created = await client.post("/api/v1/users", headers=auth_headers, json={
        "email": "td-other@scanr.local", "password": "tdother123", "role": "analyst"})
    uid = created.json()["id"]
    login = await client.post("/api/v1/auth/login", json={
        "email": "td-other@scanr.local", "password": "tdother123"})
    other = {"Authorization": f"Bearer {login.json()['access_token']}"}

    r = await client.post(
        f"/api/v1/integrations/topdesk/findings/{finding_fixture['finding_id']}/ticket",
        headers=other)
    assert r.status_code == 404, r.text

    await client.delete(f"/api/v1/users/{uid}", headers=auth_headers)


@pytest.mark.asyncio
async def test_get_ticket_returns_404_before_one_exists(client, auth_headers, finding_fixture):
    r = await client.get(
        f"/api/v1/integrations/topdesk/findings/{finding_fixture['finding_id']}/ticket",
        headers=auth_headers)
    assert r.status_code == 404
