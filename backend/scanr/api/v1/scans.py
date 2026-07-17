from __future__ import annotations

import json
import logging
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanr.db import get_db
from scanr.deps import require_scope
from scanr.models import Host, Scan, ScanStatus, Target, Finding
from scanr.models.base import new_uuid
from scanr.models.user import User
from scanr.schemas import ScanCreate, ScanRead, ScanSummary
from scanr.schemas.scan import ScanCredentialRead
from scanr.schemas.host import HostRead
from scanr.core.limiter import limiter
from scanr.utils.ip_utils import classify_target

router = APIRouter(prefix="/scans", tags=["scans"])
logger = logging.getLogger(__name__)

_PORT_RANGE_RE = re.compile(r'^(top-\d{1,5}|all|[1-9]\d{0,4}(-[1-9]\d{0,4})?(,[1-9]\d{0,4}(-[1-9]\d{0,4})?)*)$')


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
    timing: int = Field(default=4, ge=1, le=5)

    @field_validator("scanners", mode="before")
    @classmethod
    def _normalize_scanners(cls, v, info):
        """Accept old single-string 'scanner' field or new 'scanners' array.
        An explicitly-empty array means no port scanning."""
        if v is not None:
            return v
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


async def _validate_targets(targets: list[str]) -> None:
    """Reject malformed targets and any that point at scanner infrastructure."""
    from scanr.config import get_settings
    from scanr.utils.ip_utils import expand_targets as _expand, is_forbidden_target

    denylist = get_settings().scan_denylist
    for raw in targets:
        value = raw.strip()
        if is_forbidden_target(value, denylist):
            raise HTTPException(
                status_code=400,
                detail=f"Target {value!r} is not allowed (scanner infrastructure / loopback / metadata).",
            )
        try:
            expanded = list(_expand(value))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid target: {exc}")
        for ip in expanded:
            if is_forbidden_target(ip, denylist):
                raise HTTPException(
                    status_code=400,
                    detail=f"Target {value!r} expands to a disallowed address ({ip}).",
                )


async def _verify_credential_owner(
    credential_id: str | None, user_id: str, db: AsyncSession
) -> None:
    """Ensure a referenced vault credential exists and belongs to the user."""
    if not credential_id:
        return
    from scanr.models.credential import Credential

    result = await db.execute(
        select(Credential.id).where(
            Credential.id == credential_id, Credential.user_id == user_id
        )
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=404, detail="Credential not found or not owned by you"
        )


async def _resolve_ai_agent_fields(ai_agent, current_user: User, db: AsyncSession) -> dict:
    """Validate the opt-in AI agent config and map it to Scan columns.

    Returns the ai_agent_* kwargs for the Scan model. Aggressive capabilities are
    admin-only; the provider must have an API key configured so we fail fast at
    creation time rather than during the background run.
    """
    from scanr.schemas.scan import ScanAiAgentConfig

    if not isinstance(ai_agent, ScanAiAgentConfig) or not ai_agent.enabled:
        return {}

    if ai_agent.aggressive_requested() and getattr(current_user, "role", None) != "admin":
        raise HTTPException(
            status_code=403, detail="Aggressive AI capabilities require an admin user."
        )

    from scanr.ai import settings_store as store
    from scanr.ai.llm.factory import SUPPORTED_PROVIDERS

    provider_name = ai_agent.provider or await store.get_default_provider(db)
    if provider_name not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown AI provider {provider_name!r}.")
    if not await store.resolve_api_key(db, provider_name):
        raise HTTPException(
            status_code=400,
            detail=f"No API key configured for provider {provider_name!r}. Add one in Settings → AI.",
        )

    caps = {
        "aggressive": ai_agent.aggressive_requested(),
        "allow_privilege_escalation": ai_agent.allow_privilege_escalation,
        "allow_exploitation": ai_agent.allow_exploitation,
        "allow_command_exec": ai_agent.allow_command_exec,
    }
    return {
        "ai_agent_enabled": True,
        "ai_agent_mode": ai_agent.mode,
        "ai_agent_objective": ai_agent.objective.strip() or None,
        "ai_agent_provider": provider_name,
        "ai_agent_model": ai_agent.model,
        "ai_agent_capabilities": json.dumps(caps) if caps["aggressive"] else None,
    }


async def _transition_status(
    scan_id: str,
    user_id: str,
    expected: ScanStatus,
    new: ScanStatus,
    db: AsyncSession,
) -> bool:
    """Atomically move a scan from `expected` to `new` status.

    Returns True if exactly one row was updated. Doing the check and the write
    in a single conditional UPDATE avoids a check-then-set race between
    concurrent pause/resume requests.
    """
    result = await db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.user_id == user_id, Scan.status == expected)
        .values(status=new)
    )
    await db.commit()
    return result.rowcount == 1


async def _get_own_scan(scan_id: str, user_id: str, db: AsyncSession) -> Scan:
    """Load a scan and verify it belongs to the requesting user. Raises 404 if not found."""
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id, Scan.user_id == user_id)
        .options(selectinload(Scan.targets))
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
        .options(selectinload(Scan.targets))
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
    await _validate_targets(body.targets)

    if body.profile_json:
        body.profile_json = _validate_profile_json(body.profile_json)

    # Verify any referenced vault credential belongs to the requesting user
    # before binding it to the scan (prevents using another user's credential).
    await _verify_credential_owner(body.credential_id, current_user.id, db)

    ai_fields = await _resolve_ai_agent_fields(body.ai_agent, current_user, db)

    scan = Scan(
        id=new_uuid(),
        name=body.name,
        description=body.description,
        status=ScanStatus.pending,
        profile=body.profile,
        profile_json=body.profile_json,
        credential_id=body.credential_id,
        user_id=current_user.id,
        **ai_fields,
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

    # Create exclusions
    if body.exclusions:
        from scanr.models.exclusion import Exclusion
        for exc in body.exclusions:
            val = exc.strip()
            if not val:
                continue
            exc_type = "host"
            if "/" in val:
                exc_type = "cidr"
            elif val.replace(".", "").replace(":", "").isalnum() and not val.isalpha():
                exc_type = "ip"
            db.add(Exclusion(scan_id=scan.id, type=exc_type, value=val))

    scan_id = scan.id
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        logger.exception("create_scan commit failed")
        raise HTTPException(status_code=500, detail="Internal error creating scan")

    result = await db.execute(
        select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.targets))
    )
    return result.scalar_one()


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
        raise HTTPException(status_code=409, detail=f"Cannot edit scan in '{scan.status}' status — only pending scans can be modified")

    if body.name is not None:
        scan.name = body.name
    if body.description is not None:
        scan.description = body.description
    if body.profile_json is not None:
        scan.profile_json = _validate_profile_json(body.profile_json)

    if body.targets is not None:
        if not body.targets:
            raise HTTPException(status_code=400, detail="At least one target required")
        # Same denylist + expansion validation as create_scan — a PATCH must
        # not be able to point a scan at scanner infrastructure.
        await _validate_targets(body.targets)
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

    # Atomic transition: a single conditional UPDATE makes only one concurrent
    # launch win. A check-then-set would let two parallel requests both
    # dispatch Celery tasks for the same scan. Paused scans must be resumed
    # via /resume, not re-launched (would double-dispatch).
    result = await db.execute(
        update(Scan)
        .where(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
            Scan.status.notin_([ScanStatus.running, ScanStatus.paused]),
        )
        .values(status=ScanStatus.running)
    )
    await db.commit()
    if result.rowcount != 1:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot launch scan in '{scan.status}' status",
        )

    from scanr.tasks.scan_tasks import run_scan_task
    task = run_scan_task.delay(scan_id)
    await db.execute(
        update(Scan).where(Scan.id == scan_id).values(celery_task_id=task.id)
    )
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
        raise HTTPException(status_code=409, detail=f"Scan is already {scan.status}")

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
    # Atomic transition: only one concurrent request can flip running -> paused.
    if not await _transition_status(
        scan_id, current_user.id, ScanStatus.running, ScanStatus.paused, db
    ):
        raise HTTPException(status_code=409, detail="Scan is not running")
    return {"status": "paused"}


@router.post("/{scan_id}/resume", status_code=status.HTTP_202_ACCEPTED)
async def resume_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    if not await _transition_status(
        scan_id, current_user.id, ScanStatus.paused, ScanStatus.running, db
    ):
        raise HTTPException(status_code=409, detail="Scan is not paused")
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
        raise HTTPException(status_code=409, detail=f"Cannot rerun scan in status '{source.status}'")

    targets_result = await db.execute(
        select(Target.value).where(Target.scan_id == scan_id)
    )
    target_values = [row[0] for row in targets_result.all()]
    if not target_values:
        raise HTTPException(status_code=400, detail="Source scan has no targets")

    clone_id = new_uuid()
    clone = Scan(
        id=clone_id,
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
        db.add(Target(id=new_uuid(), scan_id=clone_id, value=raw, type=classify_target(raw)))

    # Copy scan-scoped credentials
    from scanr.models.scan_credential import ScanCredential
    cred_result = await db.execute(
        select(ScanCredential).where(ScanCredential.scan_id == scan_id)
    )
    for sc in cred_result.scalars().all():
        db.add(ScanCredential(
            scan_id=clone_id,
            role=sc.role,
            type=sc.type,
            username=sc.username,
            domain=sc.domain,
            encrypted_data=sc.encrypted_data,
            vault_credential_id=sc.vault_credential_id,
        ))

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create rerun scan")

    # Set status atomically before dispatching Celery task
    from scanr.tasks.scan_tasks import run_scan_task
    task = run_scan_task.delay(clone_id)
    await db.execute(
        text("UPDATE scans SET status = :status, celery_task_id = :tid WHERE id = :id"),
        {"status": ScanStatus.running.value, "tid": task.id, "id": clone_id},
    )
    await db.commit()

    result = await db.execute(
        select(Scan).where(Scan.id == clone_id).options(selectinload(Scan.targets))
    )
    return result.scalar_one()


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

    # Copy scan-scoped credentials
    from scanr.models.scan_credential import ScanCredential as _SC
    creds = await db.execute(select(_SC).where(_SC.scan_id == scan_id))
    for sc in creds.scalars().all():
        db.add(_SC(
            scan_id=clone.id, role=sc.role, type=sc.type,
            username=sc.username, domain=sc.domain,
            encrypted_data=sc.encrypted_data,
            vault_credential_id=sc.vault_credential_id,
        ))

    clone_id = clone.id
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to clone scan")

    result = await db.execute(
        select(Scan).where(Scan.id == clone_id).options(selectinload(Scan.targets))
    )
    return result.scalar_one()


@router.post("/{scan_id}/import", status_code=status.HTTP_201_CREATED)
async def import_findings(
    scan_id: str,
    body: _ImportBody,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    """Import findings from Burp Suite XML or ZAP JSON report."""
    scan = await _get_own_scan(scan_id, current_user.id, db)
    if scan.status not in (ScanStatus.completed, ScanStatus.failed, ScanStatus.pending):
        raise HTTPException(status_code=409, detail=f"Cannot import to scan in status '{scan.status}'")

    if len(body.report.encode("utf-8", errors="ignore")) > _MAX_IMPORT_BYTES:
        raise HTTPException(status_code=413, detail="Report too large (max 50 MB)")

    import xml.etree.ElementTree as ET
    imported = 0
    try:
        root = ET.fromstring(body.report)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid XML report")

    # Burp Suite XML format
    for item in root.findall(".//item"):
        title = (item.findtext("type") or item.findtext("issue") or "Imported Finding").strip()
        sev_str = (item.find(".//severity").text if item.find(".//severity") is not None else "Medium").capitalize()
        sev_map = {"High": "high", "Medium": "medium", "Low": "low", "Information": "info", "Certain": "critical"}
        severity = sev_map.get(sev_str, "medium")
        description = item.findtext("issueDetail") or item.findtext("issueBackground") or title

        # Extract request/response evidence
        evidence_parts = []
        for req_el in item.findall(".//request"):
            if req_el.text:
                evidence_parts.append(f"=== REQUEST ===\n{req_el.text.strip()}")
        for resp_el in item.findall(".//response"):
            if resp_el.text:
                evidence_parts.append(f"\n\n=== RESPONSE ===\n{resp_el.text.strip()}")
        evidence = "\n".join(evidence_parts) if evidence_parts else None

        # Extract host from request
        finding = Finding(
            id=new_uuid(),
            scan_id=scan_id,
            plugin_id="import.burp",
            severity=severity,
            title=title[:512],
            description=description,
            evidence=evidence,
        )
        db.add(finding)
        imported += 1

        # Increment counter
        sev_col = f"findings_{severity}"
        if hasattr(scan, sev_col):
            setattr(scan, sev_col, (getattr(scan, sev_col) or 0) + 1)

    if imported == 0:
        raise HTTPException(status_code=400, detail="No findings found in report")

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to import findings")
    return {"imported": imported}


_MAX_IMPORT_BYTES = 50 * 1024 * 1024  # 50 MB cap on imported report bodies


class _ImportBody(BaseModel):
    report: str = Field(max_length=_MAX_IMPORT_BYTES)  # XML/JSON report body


@router.post("/{scan_id}/findings/manual", status_code=status.HTTP_201_CREATED)
async def add_manual_finding(
    scan_id: str,
    body: _ManualFindingCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scope("scans:write")),
):
    """Add a manually verified finding to a scan."""
    scan = await _get_own_scan(scan_id, current_user.id, db)
    if scan.status not in (ScanStatus.completed, ScanStatus.failed, ScanStatus.pending):
        raise HTTPException(status_code=409, detail=f"Cannot add findings to scan in status '{scan.status}'")

    finding = Finding(
        id=new_uuid(),
        scan_id=scan_id,
        plugin_id="manual",
        severity=body.severity,
        title=body.title,
        description=body.description,
        evidence=body.evidence,
        remediation=body.remediation,
        cve_ids=json.dumps(body.cve_ids) if body.cve_ids else None,
    )
    db.add(finding)

    # Increment scan counters
    sev_col = f"findings_{body.severity}"
    if hasattr(scan, sev_col):
        setattr(scan, sev_col, (getattr(scan, sev_col) or 0) + 1)

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create finding")
    return {"id": finding.id}


class _ManualFindingCreate(BaseModel):
    title: str = Field(min_length=1, max_length=512)
    description: str = Field(min_length=1)
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    evidence: str | None = None
    remediation: str | None = None
    cve_ids: list[str] | None = None


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
        # 0. nullify self-referential FKs from other scans
        await db.execute(text(
            "UPDATE scans SET compare_scan_id = NULL WHERE compare_scan_id = :scan_id"
        ), sid)
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
        await db.execute(text("DELETE FROM scan_credentials WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM findings WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM hosts WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM targets WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM reports WHERE scan_id = :scan_id"), sid)
        await db.execute(text("DELETE FROM exclusions WHERE scan_id = :scan_id"), sid)
        # 5. scan itself
        await db.execute(text("DELETE FROM scans WHERE id = :scan_id"), sid)
    await db.commit()
