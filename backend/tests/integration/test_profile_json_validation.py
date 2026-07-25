"""Regression tests: every writer of profile_json must validate it.

profile_json reaches nmap's argument list via ScanContext.get_port_range(), and
python-nmap shlex-splits the argument string. A port_range containing whitespace
therefore becomes extra nmap flags (--script, -oN, ...). /scans validated it, but
/schedules and /templates persisted it unchecked, and the scheduler copies a
schedule's profile verbatim into a Scan at fire time.
"""
import json

import pytest

# Whitespace turns the value into additional nmap arguments once python-nmap
# shlex-splits the argument string.
INJECTION = "- --script /tmp/pwn.nse -oN /app/wordlists/x"


@pytest.mark.asyncio
async def test_scans_rejects_port_range_injection(client, auth_headers):
    r = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "pr-inject-scan",
        "targets": ["192.0.2.10"],
        "profile_json": json.dumps({"port_range": INJECTION}),
    })
    assert r.status_code == 400, r.text
    assert "port_range" in r.json()["detail"]


@pytest.mark.asyncio
async def test_scans_patch_rejects_port_range_injection(client, auth_headers):
    r = await client.post("/api/v1/scans", headers=auth_headers, json={
        "name": "pr-inject-patch", "targets": ["192.0.2.10"],
    })
    assert r.status_code == 201, r.text
    r2 = await client.patch(f"/api/v1/scans/{r.json()['id']}", headers=auth_headers, json={
        "profile_json": json.dumps({"port_range": INJECTION}),
    })
    assert r2.status_code == 400, r2.text


@pytest.mark.asyncio
async def test_schedules_reject_port_range_injection(client, auth_headers):
    r = await client.post("/api/v1/schedules", headers=auth_headers, json={
        "name": "pr-inject-sched",
        "targets": ["192.0.2.10"],
        "cron_expr": "0 3 * * *",
        "scan_profile_json": json.dumps({"port_range": INJECTION}),
    })
    assert r.status_code == 400, r.text
    assert "port_range" in r.json()["detail"]


@pytest.mark.asyncio
async def test_schedules_patch_rejects_port_range_injection(client, auth_headers):
    r = await client.post("/api/v1/schedules", headers=auth_headers, json={
        "name": "pr-inject-sched-ok",
        "targets": ["192.0.2.10"],
        "cron_expr": "0 4 * * *",
        "scan_profile_json": json.dumps({"port_range": "top-1000"}),
    })
    assert r.status_code == 201, r.text
    r2 = await client.put(f"/api/v1/schedules/{r.json()['id']}", headers=auth_headers, json={
        "scan_profile_json": json.dumps({"port_range": INJECTION}),
    })
    assert r2.status_code == 400, r2.text


@pytest.mark.asyncio
async def test_schedules_accept_valid_profile(client, auth_headers):
    """The fix must not break legitimate schedules, including non-profile keys
    (credential_id/template_id) that the scheduler reads at fire time."""
    r = await client.post("/api/v1/schedules", headers=auth_headers, json={
        "name": "pr-valid-sched",
        "targets": ["192.0.2.20"],
        "cron_expr": "0 5 * * *",
        "scan_profile_json": json.dumps({
            "port_range": "80,443,8000-8010",
            "profile": "standard",
            "template_id": None,
            "performance": {"max_concurrent_hosts": 10},
        }),
    })
    assert r.status_code == 201, r.text
    stored = json.loads(r.json()["scan_profile_json"])
    assert stored["port_range"] == "80,443,8000-8010"
    assert stored["profile"] == "standard"


@pytest.mark.asyncio
async def test_templates_reject_port_range_injection(client, auth_headers):
    r = await client.post("/api/v1/templates", headers=auth_headers, json={
        "name": "pr-inject-tpl",
        "profile_json": {"port_range": INJECTION},
    })
    assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_templates_patch_rejects_port_range_injection(client, auth_headers):
    r = await client.post("/api/v1/templates", headers=auth_headers, json={
        "name": "pr-inject-tpl-ok",
        "profile_json": {"port_range": "top-1000"},
    })
    assert r.status_code == 201, r.text
    r2 = await client.put(f"/api/v1/templates/{r.json()['id']}", headers=auth_headers, json={
        "profile_json": {"port_range": INJECTION},
    })
    assert r2.status_code == 400, r2.text


@pytest.mark.asyncio
async def test_schedules_reject_out_of_bound_performance(client, auth_headers):
    """The schema also caps resource knobs; schedules previously bypassed those."""
    r = await client.post("/api/v1/schedules", headers=auth_headers, json={
        "name": "pr-inject-perf",
        "targets": ["192.0.2.10"],
        "cron_expr": "0 6 * * *",
        "scan_profile_json": json.dumps({
            "performance": {"max_concurrent_hosts": 100000, "masscan_rate": 10_000_000},
        }),
    })
    assert r.status_code == 400, r.text
