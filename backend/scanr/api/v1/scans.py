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


class _DiscoveryConfig(BaseModel):
    icmp: bool = True
    tcp: bool = True
    arp: bool = True
    udp: bool = False
    retries: int = Field(default=1, ge=0, le=10)
    strategy: Literal["fast", "validated"] = "validated"
    mode: Literal["fast", "aggressive", "skip"] = "fast"
    assume_up: bool = False


class _PortScanningConfig(BaseModel):
    scanner: Literal["tcp_connect", "syn", "udp"] | None = None
    scanners: list[Literal["tcp_connect", "syn", "udp"]] = Field(default_factory=lambda: ["tcp_connect"])
    firewall_strategy: Literal["default", "skip_ping"] = "default"

    @field_validator("scanners", mode="before")
    @classmethod
    def _normalize_scanners(cls, v, info):
        """Accept old single-string 'scanner' field or new 'scanners' array."""
        if v is not None and len(v) > 0:
            return v
        # Fall back to legacy single-scanner field
        old = info.data.get("scanner")
        if old:
            return [old]
        return ["tcp_connect"]


class _EnumerationConfig(BaseModel):
    service_detection: bool = True
    http_probing: bool = True
    tls_checks: bool = True
    security_headers: bool = True
    screenshots: bool = True
    nuclei: bool = True
    directory_enum: bool = False
    subdomain_enum: bool = False
    dns_recon: bool = False


class _PerformanceConfig(BaseModel):
    max_concurrent_hosts: int = Field(default=20, ge=1, le=200)
    max_concurrent_plugins: int = Field(default=20, ge=1, le=100)
    timeout: int = Field(default=60, ge=1, le=3600)
    masscan_rate: int = Field(default=10000, ge=1, le=100000)
    nuclei_rate: int = Field(default=25, ge=1, le=1000)
    max_hosts: int | None = Field(default=None, ge=1, le=65536)
    max_checks: int | None = Field(default=None, ge=1, le=1000000)


class _ProfileJson(BaseModel):
    target_mode: Literal["internal", "domain", "bug_bounty", "external"] | None = None
    scan_context: Literal["internal", "external", "custom"] | None = None
    target_type: Literal["ip", "cidr", "range", "hostname", "domain"] | None = None
    safety_level: Literal["safe", "balanced", "aggressive"] | None = None
    depth_level: Literal["light", "balanced", "deep"] | None = None
    performance_profile: Literal["conservative", "normal", "fast", "custom"] | None = None
    external_recon: bool = False
    subdomain_enum: bool = True
    max_subdomains: int | None = Field(default=None, ge=0, le=1000)
    disable_masscan: bool = False
    allow_full_port_scan: bool = False
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
    discovery: _DiscoveryConfig | None = None
    port_scanning: _PortScanningConfig | None = None
    enumeration: _EnumerationConfig | None = None
    performance: _PerformanceConfig | None = None
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
    except Exception:
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


class ScanUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    targets: list[str] | None = None
    profile_json: str | None = None


@router.patch("/{scan_id}", response_model=ScanRead)
async def update_scan(
    scan_id: str,
    body: ScanUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    """Update a pending scan's settings (name, targets, profile). Only allowed before launch."""
    scan = await _get_own_scan(scan_id, current_user.id, db)
    if scan.status not in (ScanStatus.pending,):
        raise HTTPException(status_code=409, detail=f"Cannot edit scan in '{scan.status.value}' status — only pending scans can be modified")

    if body.name is not None:
        scan.name = body.name
    if body.description is not None:
        scan.description = body.description
    if body.profile_json is not None:
        scan.profile_json = _validate_profile_json(body.profile_json)

    if body.targets is not None:
        if not body.targets:
            raise HTTPException(status_code=400, detail="At least one target required")
        from scanr.utils.ip_utils import expand_targets as _expand
        for raw in body.targets:
            try:
                list(_expand(raw.strip()))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"Invalid target: {exc}")
        # Replace targets: delete old, insert new
        await db.execute(text("DELETE FROM targets WHERE scan_id = :sid"), {"sid": scan_id})
        for raw in body.targets:
            from scanr.models import Target as _Target
            db.add(_Target(id=new_uuid(), scan_id=scan_id, value=raw.strip(), type=classify_target(raw.strip())))

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update scan")
    await db.refresh(scan)
    return scan


@router.get("/{scan_id}/hosts", response_model=list[HostRead])
async def get_scan_hosts(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:read")),
):
    await _get_own_scan(scan_id, current_user.id, db)
    from scanr.models.port import Port
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


@router.post("/{scan_id}/pause", status_code=status.HTTP_202_ACCEPTED)
async def pause_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    scan = await _get_own_scan(scan_id, current_user.id, db)
    if scan.status != ScanStatus.running:
        raise HTTPException(status_code=409, detail=f"Cannot pause scan in status '{scan.status.value}'")
    scan.status = ScanStatus.paused
    await db.commit()
    return {"status": "paused"}


@router.post("/{scan_id}/resume", status_code=status.HTTP_202_ACCEPTED)
async def resume_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    scan = await _get_own_scan(scan_id, current_user.id, db)
    if scan.status != ScanStatus.paused:
        raise HTTPException(status_code=409, detail=f"Cannot resume scan in status '{scan.status.value}'")
    scan.status = ScanStatus.running
    await db.commit()
    return {"status": "running"}


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


@router.get("/{scan_id}/delta/latest")
async def scan_delta_latest(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:read")),
):
    """Compare scan_id against the most recent prior scan with overlapping targets."""
    from scanr.core.delta_engine import compute_delta

    scan = await _get_own_scan(scan_id, current_user.id, db)
    targets_result = await db.execute(select(Target.value).where(Target.scan_id == scan_id))
    target_values = {row[0] for row in targets_result.all()}
    if not target_values:
        raise HTTPException(status_code=404, detail="No targets found for scan")

    baseline_result = await db.execute(
        select(Scan)
        .join(Target, Target.scan_id == Scan.id)
        .where(
            Scan.user_id == current_user.id,
            Scan.id != scan_id,
            Scan.created_at < scan.created_at,
            Scan.status.in_([ScanStatus.completed, ScanStatus.failed]),
            Target.value.in_(target_values),
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    baseline_scan = baseline_result.scalar_one_or_none()
    if not baseline_scan:
        raise HTTPException(status_code=404, detail="No previous scan with matching targets found")

    delta = await compute_delta(baseline_scan.id, scan_id, db)
    delta["baseline_scan"] = {
        "id": baseline_scan.id,
        "name": baseline_scan.name,
        "created_at": baseline_scan.created_at.isoformat() if baseline_scan.created_at else None,
    }
    return delta


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{scan_id}/rerun", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def rerun_scan(
    request: Request,
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    """Clone a completed scan and launch it immediately with the same config."""
    source = await _get_own_scan(scan_id, current_user.id, db)
    if source.status not in (ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled):
        raise HTTPException(status_code=409, detail=f"Cannot rerun scan in status '{source.status.value}'")

    # Load original targets
    targets_result = await db.execute(
        select(Target.value).where(Target.scan_id == scan_id)
    )
    target_values = [row[0] for row in targets_result.all()]
    if not target_values:
        raise HTTPException(status_code=400, detail="Source scan has no targets")

    clone = Scan(
        id=new_uuid(),
        name=f"{source.name} (rerun)",
        description=source.description,
        status=ScanStatus.pending,
        profile=source.profile,
        profile_json=source.profile_json,
        credential_id=source.credential_id,
        template_id=source.template_id,
        compare_scan_id=source.id,
        user_id=current_user.id,
    )
    db.add(clone)

    for raw in target_values:
        db.add(Target(id=new_uuid(), scan_id=clone.id, value=raw, type=classify_target(raw)))

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create rerun scan")

    # Launch immediately
    from scanr.tasks.scan_tasks import run_scan_task
    task = run_scan_task.delay(clone.id)
    clone.status = ScanStatus.running
    clone.celery_task_id = task.id
    await db.commit()
    await db.refresh(clone)
    return clone


@router.post("/{scan_id}/clone", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def clone_scan(
    request: Request,
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    """Clone a scan as pending so the user can modify and launch it later."""
    source = await _get_own_scan(scan_id, current_user.id, db)

    targets_result = await db.execute(
        select(Target.value).where(Target.scan_id == scan_id)
    )
    target_values = [row[0] for row in targets_result.all()]
    if not target_values:
        raise HTTPException(status_code=400, detail="Source scan has no targets")

    clone = Scan(
        id=new_uuid(),
        name=f"{source.name} (copy)",
        description=source.description,
        status=ScanStatus.pending,
        profile=source.profile,
        profile_json=source.profile_json,
        credential_id=source.credential_id,
        template_id=source.template_id,
        compare_scan_id=source.id,
        user_id=current_user.id,
    )
    db.add(clone)

    for raw in target_values:
        db.add(Target(id=new_uuid(), scan_id=clone.id, value=raw, type=classify_target(raw)))

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to clone scan")

    await db.refresh(clone)
    return clone


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    await _get_own_scan(scan_id, current_user.id, db)

    # Delete in FK dependency order. The session already has an implicit transaction
    # (auto-begun by FastAPI's get_db), so use begin_nested() for a savepoint rather
    # than begin() which raises InvalidRequestError on an already-open transaction.
    sid = {"scan_id": scan_id}
    async with db.begin_nested():
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
        # 4. plugin runs plus scan-owned records
        await db.execute(text("DELETE FROM plugin_runs WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM findings WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM hosts WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM targets WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM reports WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM exclusions WHERE scan_id = :scan_id"), sid)
        # 5. scan itself
        await db.execute(text("DELETE FROM scans WHERE id = :scan_id"), sid)
    await db.commit()
