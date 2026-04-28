from __future__ import annotations

import json
import logging
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Host, Scan, ScanStatus, Target
from scanr.models.base import new_uuid
from scanr.models.user import User
from scanr.schemas import ScanCreate, ScanRead, ScanSummary
from scanr.schemas.scan import ScanCredentialRead
from scanr.schemas.host import HostRead
from scanr.core.limiter import limiter
from scanr.utils.ip_utils import classify_target

router = APIRouter(prefix="/scans", tags=["scans"])
logger = logging.getLogger(__name__)

_PORT_RANGE_RE = re.compile(r'^(top-\d{1,5}|all|\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$')


class _BruteForceConfig(BaseModel):
    enabled: bool = False
    credential_wordlist_id: str | None = None
    username_wordlist_id: str | None = None
    password_wordlist_id: str | None = None
    max_concurrent: int = Field(default=3, ge=1, le=20)
    delay_ms: int = Field(default=500, ge=0, le=30000)
    stop_on_success: bool = False
    max_failures_per_account: int = Field(default=5, ge=1, le=100)


class _ProfileJson(BaseModel):
    port_range: str | None = None
    masscan_rate: int | None = Field(default=None, ge=1, le=100000)
    plugins: list[str] | None = None
    timeout: int | None = Field(default=None, ge=1, le=3600)
    max_concurrent: int | None = Field(default=None, ge=1, le=100)
    intrusive: bool = False
    debug: bool = False
    stealth: bool = False
    credential_chain: bool = False
    xxe_probe_file: str | None = Field(default=None, max_length=200)
    brute_force: _BruteForceConfig | None = None

    @field_validator("port_range")
    @classmethod
    def _check_port_range(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _PORT_RANGE_RE.match(v):
            raise ValueError(f"Invalid port_range: {v!r}. Use e.g. 'top-1000', '80,443', '1-1024', 'all'.")
        if v.startswith("top-"):
            n = int(v[4:])
            if n > 65535:
                raise ValueError(f"top-{n} exceeds nmap maximum of 65535")
        return v


def _validate_profile_json(raw: str) -> str:
    try:
        pj = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="profile_json is not valid JSON")
    if not isinstance(pj, dict):
        raise HTTPException(status_code=400, detail="profile_json must be a JSON object")
    try:
        validated = _ProfileJson.model_validate(pj)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid profile_json: {exc}")
    return validated.model_dump_json(exclude_none=True)


async def _get_own_scan(scan_id: str, user_id: str, db: AsyncSession) -> Scan:
    """Load a scan and verify it belongs to the requesting user. Raises 404 if not found."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("", response_model=list[ScanSummary])
async def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:read")),
):
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return result.scalars().all()


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_scan(
    request: Request,
    body: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    if not body.targets:
        raise HTTPException(status_code=400, detail="At least one target required")

    # Validate targets eagerly so we reject invalid input at API time, not scan execution time
    from scanr.utils.ip_utils import expand_targets as _expand
    for raw in body.targets:
        try:
            list(_expand(raw.strip()))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid target: {exc}")

    if body.profile_json:
        body.profile_json = _validate_profile_json(body.profile_json)

    scan = Scan(
        id=new_uuid(),
        name=body.name,
        description=body.description,
        status=ScanStatus.pending,
        profile=body.profile,
        profile_json=body.profile_json,
        credential_id=body.credential_id,
        user_id=current_user.id,
    )
    db.add(scan)

    for raw in body.targets:
        target = Target(
            id=new_uuid(),
            scan_id=scan.id,
            value=raw.strip(),
            type=classify_target(raw.strip()),
        )
        db.add(target)

    # Process inline scan-scoped credentials
    if body.credentials:
        from scanr.credentials.vault import encrypt
        from scanr.models.credential import Credential
        from scanr.models.scan_credential import ScanCredential

        for cred_in in body.credentials:
            enc_data = encrypt({
                "password": cred_in.password or "",
                "domain": cred_in.domain or "",
                **(cred_in.extra or {}),
            })

            scan_cred = ScanCredential(
                scan_id=scan.id,
                role=cred_in.role,
                type=cred_in.type,
                username=cred_in.username,
                domain=cred_in.domain,
                encrypted_data=enc_data,
            )

            # Optionally save to global vault
            if cred_in.save_to_vault:
                vault_cred = Credential(
                    user_id=current_user.id,
                    name=cred_in.vault_name or f"{cred_in.role} — {scan.name}",
                    type=cred_in.type,
                    username=cred_in.username,
                    encrypted_data=enc_data,
                    description=f"Saved from scan: {scan.name}",
                )
                db.add(vault_cred)
                await db.flush()
                scan_cred.vault_credential_id = vault_cred.id

            db.add(scan_cred)

    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.exception("create_scan commit failed")
        raise HTTPException(status_code=500, detail="Internal error creating scan")
    await db.refresh(scan)
    return scan


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:read")),
):
    return await _get_own_scan(scan_id, current_user.id, db)


@router.get("/{scan_id}/hosts", response_model=list[HostRead])
async def get_scan_hosts(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:read")),
):
    await _get_own_scan(scan_id, current_user.id, db)
    from scanr.models.port import Port
    from scanr.models.service import Service
    result = await db.execute(
        select(Host)
        .where(Host.scan_id == scan_id)
        .options(selectinload(Host.ports).selectinload(Port.service))
    )
    return result.scalars().all()


@router.get("/{scan_id}/credentials", response_model=list[ScanCredentialRead])
async def get_scan_credentials(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:read")),
):
    """List credentials attached to a scan (passwords are never returned)."""
    await _get_own_scan(scan_id, current_user.id, db)
    from scanr.models.scan_credential import ScanCredential

    result = await db.execute(
        select(ScanCredential).where(ScanCredential.scan_id == scan_id)
    )
    return result.scalars().all()


@router.post("/{scan_id}/launch", status_code=status.HTTP_202_ACCEPTED)
async def launch_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    scan = await _get_own_scan(scan_id, current_user.id, db)
    if scan.status == ScanStatus.running:
        raise HTTPException(status_code=409, detail="Scan already running")

    from scanr.tasks.scan_tasks import run_scan_task
    task = run_scan_task.delay(scan_id)
    scan.status = ScanStatus.running
    scan.celery_task_id = task.id
    await db.commit()
    return {"task_id": task.id, "scan_id": scan_id}


@router.post("/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    scan = await _get_own_scan(scan_id, current_user.id, db)

    if scan.status not in (ScanStatus.pending, ScanStatus.running):
        raise HTTPException(status_code=409, detail=f"Scan is already {scan.status.value}")

    if scan.celery_task_id:
        from scanr.tasks.celery_app import celery_app
        celery_app.control.revoke(scan.celery_task_id, terminate=True, signal="SIGTERM")

    scan.status = ScanStatus.cancelled
    await db.commit()
    return {"status": "cancelled"}


@router.get("/{scan_id}/delta")
async def scan_delta(
    scan_id: str,
    baseline: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:read")),
):
    """Compare scan_id against baseline scan. Returns delta of hosts, ports, findings."""
    from scanr.core.delta_engine import compute_delta
    await _get_own_scan(scan_id, current_user.id, db)
    await _get_own_scan(baseline, current_user.id, db)
    return await compute_delta(baseline, scan_id, db)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    await _get_own_scan(scan_id, current_user.id, db)

    # Delete in FK dependency order inside a single transaction.
    sid = {"scan_id": scan_id}
    async with db.begin():
        # 1. services → ports → hosts
        await db.execute(text(
            "DELETE FROM services WHERE port_id IN "
            "(SELECT p.id FROM ports p JOIN hosts h ON p.host_id = h.id WHERE h.scan_id = :scan_id)"
        ), sid)
        await db.execute(text(
            "DELETE FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE scan_id = :scan_id)"
        ), sid)
        # 2. screenshots
        await db.execute(text("DELETE FROM screenshots WHERE scan_id = :scan_id"), sid)
        # 3. nullify first_seen/last_seen refs in findings from OTHER scans
        await db.execute(text(
            "UPDATE findings SET first_seen_scan_id = NULL WHERE first_seen_scan_id = :scan_id"
        ), sid)
        await db.execute(text(
            "UPDATE findings SET last_seen_scan_id = NULL WHERE last_seen_scan_id = :scan_id"
        ), sid)
        # 4. findings, hosts, targets, reports, exclusions
        await db.execute(text("DELETE FROM findings WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM hosts WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM targets WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM reports WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM exclusions WHERE scan_id = :scan_id"), sid)
        # 5. scan itself
        await db.execute(text("DELETE FROM scans WHERE id = :scan_id"), sid)
