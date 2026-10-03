"""Finding library: management, applying, manual findings and auto-mapping."""
import json
import uuid
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parents[1] / "fixtures" / "imports"


def entry(**kw):
    return {"title": f"Lib {uuid.uuid4().hex[:6]}", "severity": "high", "description": "Reviewed description.",
            "impact": "Reviewed impact.", "remediation": "Reviewed fix.", "references": ["https://ref.example"],
            "tags": ["web"], **kw}


async def _viewer(client, admin):
    email = f"lib-viewer-{uuid.uuid4().hex[:6]}@scanr.local"
    await client.post("/api/v1/users", json={"email": email, "password": "long-enough-pw", "role": "viewer"}, headers=admin)
    login = await client.post("/api/v1/auth/login", json={"email": email, "password": "long-enough-pw"})
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


@pytest.mark.asyncio
async def test_crud_permissions_and_duplicates(client, auth_headers):
    body = entry()
    r = await client.post("/api/v1/library", json=body, headers=auth_headers)
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    assert r.json()["created_by"] == "admin@scanr.local"
    dup = await client.post("/api/v1/library", json={**body, "title": body["title"].upper()}, headers=auth_headers)
    assert dup.status_code == 409

    upd = await client.put(f"/api/v1/library/{tid}", json={**body, "severity": "medium"}, headers=auth_headers)
    assert upd.json()["severity"] == "medium" and upd.json()["updated_by"] == "admin@scanr.local"
    found = await client.get(f"/api/v1/library?q={body['title']}", headers=auth_headers)
    assert [t["id"] for t in found.json()] == [tid]

    viewer = await _viewer(client, auth_headers)
    assert (await client.get("/api/v1/library", headers=viewer)).status_code == 200
    assert (await client.post("/api/v1/library", json=entry(), headers=viewer)).status_code == 403
    assert (await client.delete(f"/api/v1/library/{tid}", headers=viewer)).status_code == 403
    assert (await client.delete(f"/api/v1/library/{tid}", headers=auth_headers)).status_code == 204


@pytest.mark.asyncio
async def test_export_import_round_trip(client, auth_headers):
    body = entry()
    await client.post("/api/v1/library", json=body, headers=auth_headers)
    exported = (await client.get("/api/v1/library/export", headers=auth_headers)).json()
    assert exported["scanr_finding_library"] == 1
    mine = [e for e in exported["entries"] if e["title"] == body["title"]]
    assert mine and mine[0]["impact"] == "Reviewed impact."

    again = await client.post("/api/v1/library/import", json={"entries": mine}, headers=auth_headers)
    assert again.json() == {"added": 0, "updated": 0, "skipped": 1}
    changed = [{**mine[0], "impact": "New impact."}, entry()]
    r = await client.post("/api/v1/library/import", json={"entries": changed, "overwrite": True}, headers=auth_headers)
    assert r.json() == {"added": 1, "updated": 1, "skipped": 0}


@pytest.mark.asyncio
async def test_starter_library_seeds_once(db):
    from sqlalchemy import func, select

    from scanr.core import finding_library
    from scanr.models.finding_template import FindingTemplate

    count = (await db.execute(select(func.count()).select_from(FindingTemplate))).scalar_one()
    added = await finding_library.seed(db)
    assert added == (len(finding_library.STARTER) if count == 0 else 0)
    assert await finding_library.seed(db) == 0


async def _scan(client, headers):
    r = await client.post("/api/v1/scans", json={"name": "lib", "targets": ["198.51.100.30"]}, headers=headers)
    return r.json()["id"]


@pytest.mark.asyncio
async def test_manual_finding_from_library(client, auth_headers):
    tid = (await client.post("/api/v1/library", json=entry(cvss_score=7.5), headers=auth_headers)).json()["id"]
    scan_id = await _scan(client, auth_headers)
    r = await client.post(f"/api/v1/scans/{scan_id}/findings/manual", headers=auth_headers,
                          json={"template_id": tid, "host": "198.51.100.30", "port_number": 8443,
                                "evidence": "Screenshot attached; request in Burp."})
    assert r.status_code == 201, r.text
    finding = (await client.get(f"/api/v1/findings/{r.json()['id']}", headers=auth_headers)).json()
    assert finding["title"].startswith("Lib ") and finding["severity"] == "high"
    assert finding["description"] == "Reviewed description." and finding["impact"] == "Reviewed impact."
    assert finding["evidence"] == "Screenshot attached; request in Burp."
    assert finding["port_number"] == 8443 and finding["template_id"] == tid and finding["cvss_score"] == 7.5
    assert finding["priority_score"] is not None
    hosts = (await client.get(f"/api/v1/scans/{scan_id}/hosts", headers=auth_headers)).json()
    assert [h["ip"] for h in hosts] == ["198.51.100.30"]
    scan = (await client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)).json()
    assert scan["findings_high"] == 1

    bare = await client.post(f"/api/v1/scans/{scan_id}/findings/manual", json={"severity": "low"}, headers=auth_headers)
    assert bare.status_code == 422


@pytest.mark.asyncio
async def test_edit_finding_text_and_apply_template(client, auth_headers):
    scan_id = await _scan(client, auth_headers)
    fid = (await client.post(f"/api/v1/scans/{scan_id}/findings/manual", headers=auth_headers,
                             json={"title": "Custom", "description": "Draft", "severity": "low"})).json()["id"]
    r = await client.patch(f"/api/v1/findings/{fid}", headers=auth_headers,
                           json={"severity": "critical", "impact": "Full compromise", "references": [" https://x ", ""]})
    assert r.status_code == 200, r.text
    assert r.json()["severity"] == "critical" and r.json()["impact"] == "Full compromise"
    assert json.loads(r.json()["references"]) == ["https://x"] and r.json()["title"] == "Custom"
    scan = (await client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)).json()
    assert scan["findings_critical"] == 1 and scan["findings_low"] == 0

    tid = (await client.post("/api/v1/library", json=entry(severity="medium"), headers=auth_headers)).json()["id"]
    applied = await client.post(f"/api/v1/findings/{fid}/apply-template", json={"template_id": tid, "use_severity": True},
                                headers=auth_headers)
    assert applied.status_code == 200
    body = applied.json()
    assert body["title"] == "Custom" and body["severity"] == "medium" and body["template_id"] == tid
    assert body["description"] == "Reviewed description." and body["evidence"].startswith("Scanner details:\nDraft")
    usage = [t for t in (await client.get("/api/v1/library", headers=auth_headers)).json() if t["id"] == tid]
    assert usage[0]["usage_count"] == 1


@pytest.mark.asyncio
async def test_imported_findings_pick_up_mapped_entries(client, auth_headers):
    await client.post("/api/v1/library", headers=auth_headers, json=entry(
        title=f"EternalBlue {uuid.uuid4().hex[:4]}", severity="critical", plugin_ids=["nessus.97833"]))
    r = await client.post("/api/v1/scans/import", headers=auth_headers,
                          json={"name": "lib-import", "report": (FIXTURES / "sample.nessus").read_text()})
    findings = (await client.get(f"/api/v1/findings?scan_id={r.json()['scan_id']}", headers=auth_headers)).json()
    eternal = next(f for f in findings if f["plugin_id"] == "nessus.97833")
    assert eternal["description"] == "Reviewed description." and eternal["template_id"]
    assert eternal["title"].startswith("MS17-010")  # title untouched
    assert eternal["evidence"].startswith("Scanner details:\nThe remote Windows host")
    other = next(f for f in findings if f["plugin_id"] == "nessus.18405")
    assert other["template_id"] is None
