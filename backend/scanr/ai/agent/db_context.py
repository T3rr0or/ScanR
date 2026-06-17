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
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

if TYPE_CHECKING:
    from scanr.core.result_collector import ResultCollector

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
        run_id: str | None = None,
        approval_timeout: int = 300,
    ):
        self.scan_id = scan_id
        self.policy = policy
        self.budget = budget
        self.denylist = denylist
        self._db = db
        self._log = logger
        self._run_id = run_id
        self._approval_timeout = approval_timeout
        self._collector: "ResultCollector | None" = None  # lazily built; persists agent findings

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
        """Pause the run, surface the pending action on the run row, and wait for
        an operator allow/deny (signalled via Redis). Times out to deny (safe)."""
        from scanr.models import AiAgentRun
        from scanr.models.base import new_uuid

        if not self._run_id:
            # No run to attach a decision to (e.g. ad-hoc use) — deny safely.
            return False

        approval_id = new_uuid()
        run = await self._db.get(AiAgentRun, self._run_id)
        if run is not None:
            run.pending_approval = json.dumps(
                {"approval_id": approval_id, "tool": tool, "args": args, "reason": reason}
            )
            await self._db.commit()
        await self._log.warn(
            f"⏸ awaiting approval for {tool}({json.dumps(args)[:120]})", phase="ai_agent"
        )

        decision = await self._await_decision(approval_id)

        if run is not None:
            run.pending_approval = None
            await self._db.commit()
        await self._log.info(f"approval for {tool}: {decision}", phase="ai_agent")
        return decision == "allow"

    async def _await_decision(self, approval_id: str) -> str:
        import asyncio

        import redis.asyncio as aioredis

        from scanr.config import get_settings

        r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
        key = f"scanr:ai:approval:{approval_id}"
        try:
            waited = 0
            while waited < self._approval_timeout:
                val = await r.get(key)
                if val in ("allow", "deny"):
                    await r.delete(key)
                    return val
                await asyncio.sleep(2)
                waited += 2
            return "deny"  # timeout — fail closed
        finally:
            await r.aclose()

    async def run_plugin(self, plugin_id: str, host_ip: str) -> dict:
        from scanr.core import plugin_manager
        from scanr.core.context import ScanContext
        from scanr.models import Scan

        classes = plugin_manager.get_all_plugin_classes()
        plugin_cls = classes.get(plugin_id)
        if plugin_cls is None:
            raise ValueError(f"unknown plugin {plugin_id!r}")

        # Destructive plugins (write/exploit) need the exploitation capability.
        if getattr(plugin_cls, "destructive", False) and not self.policy.allows_capability("allow_exploitation"):
            return {
                "denied": True,
                "reason": f"{plugin_id} is destructive and requires the 'allow_exploitation' capability.",
            }

        host = (
            await self._db.execute(
                select(Host)
                .where(Host.scan_id == self.scan_id, Host.ip == host_ip)
                .options(selectinload(Host.ports).selectinload(Port.service))
            )
        ).scalar_one_or_none()
        if host is None:
            raise ValueError(f"host {host_ip!r} not found in this scan")

        scan = await self._db.get(Scan, self.scan_id)
        if scan is None:
            raise ValueError("scan not found")
        ctx = ScanContext(scan_id=self.scan_id, scan=scan, db=self._db, profile=scan.profile, log=self._log)

        plugin = plugin_cls()
        await self._log.info(f"agent running plugin {plugin_id} on {host_ip}", phase="ai_agent")
        findings = await plugin.check(ctx, host)

        recorded = await self._persist_findings(scan, host.id, findings or [])

        items = [
            {
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "title": f.title,
                "description": (f.description or "")[:600],
                "evidence": (f.evidence or "")[:600],
            }
            for f in (findings or [])
        ]
        return {
            "plugin": plugin_id,
            "host": host_ip,
            "count": len(items),
            "recorded": recorded,
            "findings": items,
        }

    async def run_port_scan(self, host_ip: str, ports: str | None = None) -> dict:
        from scanr.core.context import ScanContext
        from scanr.models import Scan, Service
        from scanr.models.base import new_uuid
        from scanr.scanner.port_scanner.nmap_wrapper import NmapWrapper

        known_ports = _parse_ports(ports) if ports else None

        host = (
            await self._db.execute(
                select(Host).where(Host.scan_id == self.scan_id, Host.ip == host_ip).options(selectinload(Host.ports))
            )
        ).scalar_one_or_none()
        if host is None:
            raise ValueError(f"host {host_ip!r} not found in this scan")

        scan = await self._db.get(Scan, self.scan_id)
        if scan is None:
            raise ValueError("scan not found")
        ctx = ScanContext(scan_id=self.scan_id, scan=scan, db=self._db, profile=scan.profile, log=self._log)

        await self._log.info(
            f"agent port-scanning {host_ip}" + (f" ({ports})" if ports else ""), phase="ai_agent"
        )
        data = await NmapWrapper().scan_host(host_ip, ctx, known_ports=known_ports)
        scanned = (data or {}).get("ports", []) if data else []

        existing = {(p.number, p.protocol) for p in host.ports}
        added = 0
        for p in scanned:
            key = (p["number"], p["protocol"])
            if key in existing:
                continue
            existing.add(key)
            port = Port(
                id=new_uuid(), host_id=host.id, number=p["number"], protocol=p["protocol"],
                state=p["state"], reason=p.get("reason"), banner=p.get("banner"),
            )
            self._db.add(port)
            await self._db.flush()
            svc = p.get("service")
            if svc:
                self._db.add(Service(
                    id=new_uuid(), port_id=port.id, name=svc.get("name"), product=svc.get("product"),
                    version=svc.get("version"), extra_info=svc.get("extra_info"), cpe=svc.get("cpe"),
                    tunnel=svc.get("tunnel"),
                ))
            added += 1
        await self._db.commit()

        return {
            "host": host_ip,
            "open_ports": [
                {"number": p["number"], "protocol": p["protocol"], "service": (p.get("service") or {}).get("name")}
                for p in scanned
            ],
            "added": added,
        }

    async def run_command(self, command: str) -> dict:
        from scanr.sandbox.client import SandboxClient, SandboxUnavailable

        client = SandboxClient.from_settings()
        if client is None:
            return {"denied": True, "reason": "command sandbox not configured (SANDBOX_RUNNER_URL unset)."}

        scope = await self._scope_cidrs()
        if not scope:
            return {"denied": True, "reason": "no in-scope targets to constrain the sandbox to."}

        await self._log.warn(f"agent running command in sandbox: {command[:160]}", phase="ai_agent")
        try:
            result = await client.run(command=command, scope=scope, run_id=self._run_id or "")
        except SandboxUnavailable as exc:
            await self._log.error(f"sandbox unavailable: {exc}", phase="ai_agent")
            return {"denied": True, "reason": f"sandbox unavailable: {exc}"}
        return {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "truncated": result.truncated,
            "timed_out": result.timed_out,
        }

    async def _scope_cidrs(self) -> list[str]:
        """The scan's authorized targets (filtered through is_forbidden_target),
        used to constrain the sandbox's egress. Falls back to discovered host IPs."""
        from scanr.models import Target
        from scanr.utils.ip_utils import is_forbidden_target

        rows = await self._db.execute(select(Target.value).where(Target.scan_id == self.scan_id))
        targets = [str(t) for t in rows.scalars().all()]
        if not targets:
            hrows = await self._db.execute(select(Host.ip).where(Host.scan_id == self.scan_id))
            targets = [str(ip) for ip in hrows.scalars().all()]
        return [t for t in targets if t and not is_forbidden_target(t, self.denylist)]

    async def _persist_findings(self, scan, host_id: str, findings: list) -> int:
        """Route plugin findings through ResultCollector so agent discoveries
        become first-class findings (deduped, counted, shown in the UI)."""
        if not findings:
            return 0
        from scanr.core.result_collector import ResultCollector

        if self._collector is None:
            self._collector = ResultCollector(
                self.scan_id, self._db, scan_log=self._log, user_id=getattr(scan, "user_id", None)
            )
        recorded = 0
        for f in findings:
            try:
                await self._collector.add_finding(host_id, f)
                recorded += 1
            except Exception as exc:  # noqa: BLE001 - never let persistence break the run
                await self._log.warn(f"could not record agent finding: {exc}", phase="ai_agent")
        return recorded


def _parse_ports(spec: str) -> list[int]:
    """Parse a port spec like '80,443,8000-8010' into a bounded list of ints."""
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"invalid port range {part!r}")
            out.extend(range(lo, hi + 1))
        else:
            n = int(part)
            if n < 1 or n > 65535:
                raise ValueError(f"invalid port {part!r}")
            out.append(n)
        if len(out) > 2000:
            raise ValueError("too many ports (max 2000)")
    return sorted(set(out))
