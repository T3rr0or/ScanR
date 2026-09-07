"""Exclusions remain immutable once execution can observe their snapshot."""

from types import SimpleNamespace

import pytest
from sqlalchemy import select, update


async def _create_scan_with_exclusions(client, auth_headers, name: str) -> str:
    response = await client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={
            "name": name,
            "targets": ["192.0.2.10"],
            "profile": "quick",
            "exclusions": ["198.51.100.7"],
        },
    )
    assert response.status_code == 201, response.text
    scan_id = response.json()["id"]

    response = await client.post(
        f"/api/v1/scans/{scan_id}/exclusions",
        headers=auth_headers,
        json={"type": "port", "value": "8443", "reason": "maintenance"},
    )
    assert response.status_code == 201, response.text
    return scan_id


async def _exclusion_rows(client, auth_headers, scan_id: str) -> list[dict]:
    response = await client.get(
        f"/api/v1/scans/{scan_id}/exclusions", headers=auth_headers
    )
    assert response.status_code == 200, response.text
    return response.json()


def _policy(rows: list[dict]) -> set[tuple[str, str, str | None]]:
    return {(row["type"], row["value"], row["reason"]) for row in rows}


@pytest.mark.asyncio
async def test_clone_preserves_complete_exclusion_policy(client, auth_headers):
    source_id = await _create_scan_with_exclusions(
        client, auth_headers, "clone-exclusion-source"
    )

    response = await client.post(
        f"/api/v1/scans/{source_id}/clone", headers=auth_headers
    )
    assert response.status_code == 201, response.text
    clone_id = response.json()["id"]

    source_rows = await _exclusion_rows(client, auth_headers, source_id)
    clone_rows = await _exclusion_rows(client, auth_headers, clone_id)
    assert _policy(clone_rows) == _policy(source_rows)
    assert {row["id"] for row in clone_rows}.isdisjoint(
        row["id"] for row in source_rows
    )
    assert {row["scan_id"] for row in clone_rows} == {clone_id}


@pytest.mark.asyncio
async def test_rerun_preserves_complete_exclusion_policy(
    client, auth_headers, db, monkeypatch
):
    from scanr.models import Scan, ScanStatus
    from scanr.tasks.scan_tasks import run_scan_task

    source_id = await _create_scan_with_exclusions(
        client, auth_headers, "rerun-exclusion-source"
    )
    await db.execute(
        update(Scan)
        .where(Scan.id == source_id)
        .values(status=ScanStatus.completed)
    )
    await db.commit()
    monkeypatch.setattr(
        run_scan_task, "delay", lambda _scan_id: SimpleNamespace(id="test-task-id")
    )

    response = await client.post(
        f"/api/v1/scans/{source_id}/rerun", headers=auth_headers
    )
    assert response.status_code == 202, response.text
    rerun_id = response.json()["id"]

    source_rows = await _exclusion_rows(client, auth_headers, source_id)
    rerun_rows = await _exclusion_rows(client, auth_headers, rerun_id)
    assert _policy(rerun_rows) == _policy(source_rows)
    assert {row["id"] for row in rerun_rows}.isdisjoint(
        row["id"] for row in source_rows
    )
    assert {row["scan_id"] for row in rerun_rows} == {rerun_id}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scan_status",
    ["running", "paused", "completed", "failed", "cancelled"],
)
async def test_exclusions_are_immutable_after_pending(
    client, auth_headers, db, scan_status
):
    from scanr.models import Exclusion, Scan, Target
    from scanr.models.base import new_uuid
    from scanr.models.user import User

    user_id = (
        await db.execute(
            select(User.id).where(User.email == "admin@scanr.local")
        )
    ).scalar_one()
    scan = Scan(
        id=new_uuid(),
        name=f"immutable-exclusions-{scan_status}",
        status=scan_status,
        user_id=user_id,
    )
    exclusion = Exclusion(
        id=new_uuid(),
        scan_id=scan.id,
        type="ip",
        value="198.51.100.9",
        reason="must remain",
    )
    db.add(scan)
    await db.flush()
    db.add_all(
        [
            Target(
                id=new_uuid(), scan_id=scan.id, value="192.0.2.10", type="ip"
            ),
            exclusion,
        ]
    )
    await db.commit()

    create_response = await client.post(
        f"/api/v1/scans/{scan.id}/exclusions",
        headers=auth_headers,
        json={"type": "port", "value": "22"},
    )
    assert create_response.status_code == 409, create_response.text

    delete_response = await client.delete(
        f"/api/v1/scans/{scan.id}/exclusions/{exclusion.id}",
        headers=auth_headers,
    )
    assert delete_response.status_code == 409, delete_response.text

    await db.rollback()
    rows = (
        await db.execute(select(Exclusion).where(Exclusion.scan_id == scan.id))
    ).scalars().all()
    assert [(row.type, row.value, row.reason) for row in rows] == [
        ("ip", "198.51.100.9", "must remain")
    ]
