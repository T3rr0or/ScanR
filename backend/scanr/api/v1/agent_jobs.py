"""
Agent job queue — endpoints called BY the agent, not by the UI.
Authentication: X-Agent-Token header.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.core.limiter import limiter
from scanr.db import get_db
from scanr.deps import get_current_user
from scanr.models import Finding, Host, Port, Scan, ScanStatus, Service, Target
from scanr.models.base import new_uuid
from scanr.models.scan_agent import ScanAgent
from scanr.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/agent", tags=["agent-jobs"])

_RUNNER_PATH = Path(__file__).parent.parent.parent / "agent" / "runner.py"


@router.get("/script", response_class=PlainTextResponse, include_in_schema=False)
async def download_agent_script(current_user: User = Depends(get_current_user)):
    """Serve the standalone agent script — requires authentication."""
    resolved = _RUNNER_PATH.resolve()
    base = (Path(__file__).parent.parent.parent / "agent").resolve()
    if not resolved.is_relative_to(base) or not resolved.exists():
        raise HTTPException(status_code=404, detail="Agent script not found")
    content = resolved.read_text()
    return PlainTextResponse(
        content,
        media_type="text/x-python",
        headers={"Content-Disposition": "attachment; filename=scanr_agent.py"},
    )


async def _get_agent(
    x_agent_token: str = Header(..., alias="X-Agent-Token"),
    db: AsyncSession = Depends(get_db),
) -> ScanAgent:
    h = hashlib.sha256(x_agent_token.encode()).hexdigest()
    result = await db.execute(
        select(ScanAgent).where(ScanAgent.token_hash == h, ScanAgent.enabled == True)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return agent


# ── Heartbeat ──────────────────────────────────────────────────────────────

class HeartbeatBody(BaseModel):
    version: str | None = Field(None, max_length=50)  # agents.agent_version is String(50)


@router.post("/heartbeat", status_code=200)
@limiter.limit("20/minute")
async def agent_heartbeat(
    request: Request,
    body: HeartbeatBody,
    agent: ScanAgent = Depends(_get_agent),
    db: AsyncSession = Depends(get_db),
):
    agent.last_seen_at = datetime.now(timezone.utc)
    agent.ip_address = request.client.host if request.client else None
    if body.version:
        agent.agent_version = body.version
    await db.commit()
    return {"status": "ok", "agent_id": agent.id}


# ── Job queue ──────────────────────────────────────────────────────────────

@router.get("/jobs")
@limiter.limit("30/minute")
async def get_agent_jobs(
    request: Request,
    agent: ScanAgent = Depends(_get_agent),
    db: AsyncSession = Depends(get_db),
):
    """Return pending scans assigned to this agent."""
    result = await db.execute(
        select(Scan).where(
            Scan.agent_id == agent.id,
            Scan.status == ScanStatus.pending,
        )
    )
    scans = result.scalars().all()

    jobs = []
    for scan in scans:
        targets_result = await db.execute(select(Target).where(Target.scan_id == scan.id))
        targets = [t.value for t in targets_result.scalars().all()]

        profile = json.loads(scan.profile_json) if scan.profile_json else {}
        jobs.append({
            "scan_id": scan.id,
            "targets": targets,
            "port_range": profile.get("port_range", "top-1000"),
        })
    return jobs


@router.post("/jobs/{scan_id}/start", status_code=200)
@limiter.limit("20/minute")
async def agent_start_job(
    request: Request,
    scan_id: str,
    agent: ScanAgent = Depends(_get_agent),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.agent_id == agent.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Only a pending job may be started. Without this an agent could reopen a
    # finished scan and re-submit results into it.
    if scan.status != ScanStatus.pending:
        raise HTTPException(
            status_code=409,
            detail=f"Scan is not pending (status={scan.status}); it cannot be started.",
        )
    scan.status = ScanStatus.running
    agent.last_seen_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "started"}


# ── Results submission ──────────────────────────────────────────────────────

# Caps on a single results submission. An agent token is a bearer credential on
# a remote host we do not control, so the payload is untrusted input: every list
# is bounded and every string is bounded to its DB column width, or a compromised
# /leaked token could exhaust the database or trigger a write error mid-transaction.
_MAX_HOSTS_PER_SUBMIT = 4096
_MAX_PORTS_PER_HOST = 65535
_MAX_FINDINGS_PER_SUBMIT = 10000


class ServiceIn(BaseModel):
    """Bounded to the services table's column widths."""
    name: str | None = Field(None, max_length=100)
    product: str | None = Field(None, max_length=255)
    version: str | None = Field(None, max_length=100)
    extra_info: str | None = Field(None, max_length=512)
    tunnel: str | None = Field(None, max_length=20)


class PortIn(BaseModel):
    number: int = Field(..., ge=1, le=65535)
    # ports.protocol is String(5), ports.state String(20) — the literals fit.
    protocol: Literal["tcp", "udp", "sctp"] = "tcp"
    state: Literal["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"] = "open"
    banner: str | None = Field(None, max_length=1024)
    service: ServiceIn | None = None


class HostIn(BaseModel):
    ip: str = Field(..., max_length=45)  # hosts.ip is String(45)
    hostname: str | None = Field(None, max_length=255)
    status: Literal["up", "down", "unknown"] = "up"
    ports: list[PortIn] = Field(default_factory=list, max_length=_MAX_PORTS_PER_HOST)

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")
        return v


class FindingIn(BaseModel):
    host_ip: str = Field(..., max_length=45)
    plugin_id: str = Field(..., max_length=100)
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str = Field(..., max_length=500)
    description: str | None = Field(None, max_length=10000)  # Text column
    evidence: str | None = Field(None, max_length=10000)     # Text column
    port_number: int | None = Field(None, ge=1, le=65535)
    protocol: str | None = Field(None, max_length=5)  # findings.protocol is String(5)


class AgentResults(BaseModel):
    hosts: list[HostIn] = Field(default_factory=list, max_length=_MAX_HOSTS_PER_SUBMIT)
    findings: list[FindingIn] = Field(default_factory=list, max_length=_MAX_FINDINGS_PER_SUBMIT)


@router.post("/jobs/{scan_id}/results", status_code=200)
@limiter.limit("10/minute")
async def agent_submit_results(
    request: Request,
    scan_id: str,
    body: AgentResults,
    agent: ScanAgent = Depends(_get_agent),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.agent_id == agent.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Results may only be submitted once, for a running scan. Re-submitting used
    # to append duplicate hosts/findings (there is no unique constraint on
    # (scan_id, ip)) while re-incrementing the severity counters each time.
    if scan.status != ScanStatus.running:
        raise HTTPException(
            status_code=409,
            detail=f"Scan is not running (status={scan.status}); results already submitted.",
        )

    # Build ip → host_id map for linking findings
    ip_to_host_id: dict[str, str] = {}
    # ip → status as actually persisted (first occurrence wins, matching the
    # dedup below) so the scan counters match the stored rows.
    persisted_status: dict[str, str] = {}

    for h_in in body.hosts:
        # One Host row per IP: a payload repeating an IP would otherwise create
        # duplicate rows, of which only the last would be reachable via the
        # ip → host_id map used to link findings.
        if h_in.ip in ip_to_host_id:
            continue
        host = Host(
            id=new_uuid(),
            scan_id=scan_id,
            ip=h_in.ip,
            hostname=h_in.hostname,
            status=h_in.status,
        )
        db.add(host)
        await db.flush()
        ip_to_host_id[h_in.ip] = host.id
        persisted_status[h_in.ip] = h_in.status

        for p_in in h_in.ports:
            port = Port(
                id=new_uuid(),
                host_id=host.id,
                number=p_in.number,
                protocol=p_in.protocol,
                state=p_in.state,
                banner=p_in.banner,
            )
            db.add(port)
            await db.flush()

            if p_in.service:
                svc = Service(
                    id=new_uuid(),
                    port_id=port.id,
                    name=p_in.service.name,
                    product=p_in.service.product,
                    version=p_in.service.version,
                    extra_info=p_in.service.extra_info,
                    tunnel=p_in.service.tunnel,
                )
                db.add(svc)

    from scanr.core.compliance import tags_for_plugin
    from scanr.core.mitre import mitre_tags_for_plugin

    for f_in in body.findings:
        host_id = ip_to_host_id.get(f_in.host_ip)
        compliance_tags = tags_for_plugin(f_in.plugin_id)
        mitre_tags = mitre_tags_for_plugin(f_in.plugin_id)
        finding = Finding(
            id=new_uuid(),
            scan_id=scan_id,
            host_id=host_id,
            plugin_id=f_in.plugin_id,
            severity=f_in.severity,
            title=f_in.title,
            description=f_in.description,
            evidence=f_in.evidence,
            port_number=f_in.port_number,
            protocol=f_in.protocol,
            compliance_tags=json.dumps(compliance_tags) if compliance_tags else None,
            mitre_tags=json.dumps(mitre_tags) if mitre_tags else None,
            first_seen_scan_id=scan_id,
            last_seen_scan_id=scan_id,
        )
        db.add(finding)

    # Update scan stats. Count the deduplicated hosts actually persisted, not
    # the raw payload length.
    scan.hosts_total = len(persisted_status)
    scan.hosts_up = sum(1 for status in persisted_status.values() if status == "up")
    for f_in in body.findings:
        col = {
            "critical": "findings_critical", "high": "findings_high",
            "medium": "findings_medium", "low": "findings_low",
        }.get(f_in.severity, "findings_info")
        setattr(scan, col, getattr(scan, col) + 1)

    scan.status = ScanStatus.completed
    scan.finished_at = datetime.now(timezone.utc)
    agent.last_seen_at = datetime.now(timezone.utc)

    await db.commit()
    # Report what was persisted (deduplicated), not the raw payload length.
    return {"status": "ok", "hosts": len(persisted_status), "findings": len(body.findings)}


class AgentFailBody(BaseModel):
    error: str = Field(default="Agent reported failure", max_length=2000)


@router.post("/jobs/{scan_id}/fail", status_code=200)
@limiter.limit("10/minute")
async def agent_fail_job(
    request: Request,
    scan_id: str,
    body: AgentFailBody,
    agent: ScanAgent = Depends(_get_agent),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.agent_id == agent.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Don't let a late failure report overwrite an already-terminal scan.
    if scan.status not in (ScanStatus.pending, ScanStatus.running):
        raise HTTPException(
            status_code=409,
            detail=f"Scan is already finished (status={scan.status}).",
        )
    scan.status = ScanStatus.failed
    scan.error_message = body.error[:500]
    scan.finished_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "ok"}
