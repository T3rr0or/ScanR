"""DB/engine-backed AgentContext — the real implementation the agent runs against.

Reads the scan's findings/hosts from the database, streams the agent's actions
to the live scan console (Redis pub/sub via ScanLogger), and gates approvals.

Approval channel note: interactive operator approval over WebSocket is not built
yet, so request_approval denies by default. That makes guided mode safe — any
intrusive action is skipped until approval is wired — while autonomous mode runs
the non-intrusive tool set without needing it.
"""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanr.ai.agent.context import AgentContext
from scanr.ai.agent.policy import AgentPolicy, Budget
from scanr.core.scan_logger import ScanLogger
from scanr.models import Finding, Host, Port


class DbAgentContext(AgentContext):
    def __init__(
        self,
        *,
        scan_id: str,
        db: AsyncSession,
        policy: AgentPolicy,
        budget: Budget,
        denylist: set[str],
        logger: ScanLogger,
    ):
        self.scan_id = scan_id
        self.policy = policy
        self.budget = budget
        self.denylist = denylist
        self._db = db
        self._log = logger

    async def list_hosts(self) -> list[dict]:
        rows = await self._db.execute(
            select(Host)
            .where(Host.scan_id == self.scan_id)
            .options(selectinload(Host.ports).selectinload(Port.service))
        )
        out: list[dict] = []
        for h in rows.scalars().all():
            out.append({
                "ip": h.ip,
                "hostname": h.hostname,
                "os": h.os_name,
                "ports": [
                    {
                        "number": p.number,
                        "protocol": p.protocol,
                        "service": (p.service.name if p.service else None),
                        "product": (p.service.product if p.service else None),
                        "version": (p.service.version if p.service else None),
                    }
                    for p in h.ports
                ],
            })
        return out

    async def list_findings(self, severity: str | None = None) -> list[dict]:
        q = (
            select(Finding, Host.ip.label("host_ip"))
            .outerjoin(Host, Finding.host_id == Host.id)
            .where(Finding.scan_id == self.scan_id)
        )
        if severity:
            q = q.where(Finding.severity == severity)
        rows = (await self._db.execute(q)).all()
        return [
            {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "host_ip": ip,
                "port": f.port_number,
                "plugin_id": f.plugin_id,
            }
            for f, ip in rows
        ]

    async def get_finding(self, finding_id: str) -> dict | None:
        row = (
            await self._db.execute(
                select(Finding, Host.ip.label("host_ip"))
                .outerjoin(Host, Finding.host_id == Host.id)
                .where(Finding.id == finding_id, Finding.scan_id == self.scan_id)
            )
        ).first()
        if row is None:
            return None
        f, ip = row
        return {
            "id": f.id,
            "severity": f.severity,
            "title": f.title,
            "host_ip": ip,
            "port": f.port_number,
            "plugin_id": f.plugin_id,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "cvss_score": f.cvss_score,
        }

    async def log(self, message: str) -> None:
        await self._log.info(message, phase="ai_agent")

    async def request_approval(self, tool: str, args: dict, reason: str) -> bool:
        # Interactive approval is not wired yet — deny so guided-mode intrusive
        # actions are safely skipped rather than blocking the run forever.
        await self._log.warn(
            f"approval required for {tool}({json.dumps(args)[:120]}) — denied "
            "(operator approval channel not yet available)",
            phase="ai_agent",
        )
        return False
