"""Importing other tools' results into scans."""
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parents[1] / "fixtures" / "imports"


async def _import_new(client, headers, name, fmt="auto"):
    return await client.post("/api/v1/scans/import", headers=headers,
                             json={"name": name, "report": (FIXTURES / fmt_file(name)).read_text(), "format": fmt})


def fmt_file(name: str) -> str:
    return {"nessus": "sample.nessus", "nmap": "sample-nmap.xml", "nuclei": "sample-nuclei.jsonl",
            "burp": "sample-burp.xml", "zap": "sample-zap.json"}[name]


@pytest.mark.asyncio
async def test_import_nessus_as_new_scan(client, auth_headers):
    r = await _import_new(client, auth_headers, "nessus")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["source"] == "nessus" and body["hosts_added"] == 1 and body["ports_added"] == 2
    assert body["findings_added"] == 3 and body["duplicates_skipped"] == 0

    scan = (await client.get(f"/api/v1/scans/{body['scan_id']}", headers=auth_headers)).json()
    assert scan["status"] == "completed" and scan["profile"] == "imported"
    assert scan["findings_critical"] == 1 and scan["findings_medium"] == 1 and scan["hosts_up"] == 1

    hosts = (await client.get(f"/api/v1/scans/{body['scan_id']}/hosts", headers=auth_headers)).json()
    assert hosts[0]["ip"] == "10.10.1.5" and hosts[0]["hostname"] == "fs01.corp.example"

    findings = (await client.get(f"/api/v1/findings?scan_id={body['scan_id']}&sort=priority", headers=auth_headers)).json()
    top = findings[0]
    assert top["title"].startswith("MS17-010") and top["host_ip"] == "10.10.1.5" and top["port_number"] == 445
    assert top["priority_score"] is not None and "CVE-2017-0144" in top["cve_ids"]

    launch = await client.post(f"/api/v1/scans/{body['scan_id']}/launch", headers=auth_headers)
    assert launch.status_code == 409


@pytest.mark.asyncio
async def test_import_into_existing_scan_merges_and_is_idempotent(client, auth_headers):
    scan_id = (await _import_new(client, auth_headers, "nessus")).json()["scan_id"]
    nmap = (FIXTURES / "sample-nmap.xml").read_text()
    first = await client.post(f"/api/v1/scans/{scan_id}/import", json={"report": nmap}, headers=auth_headers)
    assert first.status_code == 201, first.text
    # Same host as the Nessus file: no new host, one new port (22), two findings.
    assert first.json()["hosts_added"] == 0 and first.json()["ports_added"] == 1
    assert first.json()["findings_added"] == 2
    again = await client.post(f"/api/v1/scans/{scan_id}/import", json={"report": nmap}, headers=auth_headers)
    assert again.json()["findings_added"] == 0 and again.json()["duplicates_skipped"] == 2
    scan = (await client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)).json()
    assert scan["findings_high"] == 1 and scan["findings_info"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("fmt", ["nuclei", "burp", "zap"])
async def test_other_formats(client, auth_headers, fmt):
    r = await _import_new(client, auth_headers, fmt)
    assert r.status_code == 201, r.text
    assert r.json()["source"] == fmt and r.json()["findings_added"] >= 1


@pytest.mark.asyncio
async def test_rejects_bad_input_and_other_users_scans(client, auth_headers):
    bad = await client.post("/api/v1/scans/import", json={"name": "x", "report": "not a report"}, headers=auth_headers)
    assert bad.status_code == 400 and "Unrecognised" in bad.json()["detail"]
    wrong = await client.post("/api/v1/scans/import", headers=auth_headers,
                              json={"name": "x", "report": (FIXTURES / "sample-nmap.xml").read_text(), "format": "nessus"})
    assert wrong.status_code == 400

    scan_id = (await _import_new(client, auth_headers, "zap")).json()["scan_id"]
    await client.post("/api/v1/users", json={"email": "import-other@scanr.local", "password": "long-enough-pw"},
                      headers=auth_headers)
    login = await client.post("/api/v1/auth/login", json={"email": "import-other@scanr.local", "password": "long-enough-pw"})
    other = {"Authorization": f"Bearer {login.json()['access_token']}"}
    r = await client.post(f"/api/v1/scans/{scan_id}/import", json={"report": (FIXTURES / "sample-zap.json").read_text()},
                          headers=other)
    assert r.status_code == 404
