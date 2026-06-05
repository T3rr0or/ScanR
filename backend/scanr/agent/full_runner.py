"""
ScanR Full Agent — runs the complete ScanR plugin engine locally.

Requires the full ScanR package (same Docker image as the worker).
Use this when you need more than nmap: web plugins, SSL inspection,
service brute-force, CVE matching, etc.

Usage (Docker — recommended):
    docker run --rm \\
      -e SCANR_SERVER=https://your-scanr-server.com \\
      -e SCANR_TOKEN=sk_agent_... \\
      --network host \\
      <your-scanr-worker-image> \\
      python -m scanr.agent.full_runner

Or directly (if scanr package is installed):
    SCANR_SERVER=https://... SCANR_TOKEN=sk_agent_... \\
        python -m scanr.agent.full_runner
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import tempfile

import httpx

logger = logging.getLogger("scanr.agent.full")

POLL_INTERVAL = 30
AGENT_VERSION = "0.1.0-full"

_VERIFY_SSL = os.environ.get("SCANR_INSECURE", "").lower() not in ("1", "true", "yes")
_CA_BUNDLE = os.environ.get("SCANR_CA_BUNDLE", None)


class FullAgentRunner:
    def __init__(self, server_url: str, token: str, poll_interval: int = POLL_INTERVAL):
        self.server_url = server_url.rstrip("/")
        self.poll_interval = poll_interval
        self.headers = {
            "X-Agent-Token": token,
            "User-Agent": f"ScanR-FullAgent/{AGENT_VERSION}",
        }

    async def run(self) -> None:
        logger.info("ScanR Full Agent starting — server: %s", self.server_url)
        async with httpx.AsyncClient(timeout=30, verify=_VERIFY_SSL) as client:
            try:
                r = await client.post(
                    f"{self.server_url}/api/v1/agent/heartbeat",
                    headers=self.headers,
                    json={"version": AGENT_VERSION},
                )
                if r.status_code == 200:
                    logger.info("Agent registered/heartbeat OK")
                else:
                    logger.warning("Heartbeat returned %s: %s", r.status_code, r.text)
            except Exception as e:
                logger.error("Cannot reach server: %s", e)
                sys.exit(1)

        while True:
            try:
                await self._poll_and_run()
            except Exception as exc:
                logger.error("Poll error: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def _poll_and_run(self) -> None:
        async with httpx.AsyncClient(timeout=60, verify=_VERIFY_SSL) as client:
            r = await client.get(f"{self.server_url}/api/v1/agent/jobs", headers=self.headers)
            if r.status_code != 200:
                logger.debug("No jobs (HTTP %s)", r.status_code)
                return
            jobs = r.json()
            if not jobs:
                return
            logger.info("%d job(s) pending", len(jobs))
            for job in jobs:
                await self._run_job(job, client)

    async def _run_job(self, job: dict, client: httpx.AsyncClient) -> None:
        scan_id = job["scan_id"]
        targets = job["targets"]
        port_range = job.get("port_range", "top-1000")
        logger.info("Job %s — full scan of %d target(s) (port_range=%s)", scan_id, len(targets), port_range)

        await client.post(
            f"{self.server_url}/api/v1/agent/jobs/{scan_id}/start",
            headers=self.headers,
        )

        try:
            results = await self._run_full_scan(scan_id, targets, port_range)
            r = await client.post(
                f"{self.server_url}/api/v1/agent/jobs/{scan_id}/results",
                headers=self.headers,
                json=results,
                timeout=120,
            )
            if r.status_code == 200:
                logger.info(
                    "Job %s — results submitted (%d hosts, %d findings)",
                    scan_id, len(results.get("hosts", [])), len(results.get("findings", [])),
                )
            else:
                logger.error("Job %s — results rejected: %s", scan_id, r.text)
        except Exception as exc:
            logger.error("Job %s failed: %s", scan_id, exc, exc_info=True)
            await client.post(
                f"{self.server_url}/api/v1/agent/jobs/{scan_id}/fail",
                headers=self.headers,
                json={"error": str(exc)},
            )

    async def _run_full_scan(self, scan_id: str, targets: list[str], port_range: str) -> dict:
        """Run the full ScanR plugin engine against targets in a temp local SQLite DB."""
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
        from sqlalchemy.pool import StaticPool

        from scanr.core.engine import ScanEngine
        from scanr.db.init_db import seed_plugins
        from scanr.models import Host, Port
        from scanr.models import Finding as FindingModel
        from scanr.models import Scan, Target
        from scanr.models.base import Base, new_uuid
        from scanr.models.scan import ScanStatus

        db_fd, db_path = tempfile.mkstemp(prefix=f"scanr_agent_{scan_id[:8]}_", suffix=".db")
        os.close(db_fd)
        db_url = f"sqlite+aiosqlite:///{db_path}"

        sa_engine = create_async_engine(
            db_url,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
            echo=False,
        )

        try:
            # Create all tables
            async with sa_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            session_factory = async_sessionmaker(
                sa_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False,
            )

            dummy_user_id = new_uuid()
            profile_json = json.dumps({"port_range": port_range})

            # Seed plugins + create scan record
            async with session_factory() as session:
                await seed_plugins(session)

                scan = Scan(
                    id=scan_id,
                    name=f"Agent Scan {scan_id[:8]}",
                    status=ScanStatus.running,
                    profile="custom",
                    profile_json=profile_json,
                    user_id=dummy_user_id,
                )
                session.add(scan)
                for target_val in targets:
                    session.add(Target(id=new_uuid(), scan_id=scan_id, value=target_val))
                await session.commit()

            # Run the full scan engine
            async with session_factory() as session:
                engine = ScanEngine(scan_id, session)
                await engine.run()

            # Read results back and serialize
            from sqlalchemy import select
            from sqlalchemy.orm import selectinload

            async with session_factory() as session:
                hosts_result = await session.execute(
                    select(Host)
                    .where(Host.scan_id == scan_id)
                    .options(selectinload(Host.ports).selectinload(Port.service))
                )
                hosts = hosts_result.scalars().all()

                findings_result = await session.execute(
                    select(FindingModel, Host.ip.label("host_ip"))
                    .outerjoin(Host, FindingModel.host_id == Host.id)
                    .where(FindingModel.scan_id == scan_id)
                )
                finding_rows = findings_result.all()

            hosts_out = []
            for host in hosts:
                ports_out = []
                for port in host.ports:
                    svc = None
                    if port.service:
                        svc = {
                            "name": port.service.name,
                            "product": port.service.product,
                            "version": port.service.version,
                            "extra_info": port.service.extra_info,
                            "tunnel": port.service.tunnel,
                        }
                    ports_out.append({
                        "number": port.number,
                        "protocol": port.protocol,
                        "state": port.state,
                        "banner": port.banner,
                        "service": svc,
                    })
                hosts_out.append({
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "status": host.status,
                    "ports": ports_out,
                })

            findings_out = []
            for row in finding_rows:
                f = row[0]
                host_ip = row[1] or ""
                findings_out.append({
                    "host_ip": host_ip,
                    "plugin_id": f.plugin_id,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "port_number": f.port_number,
                    "protocol": f.protocol,
                })

            return {"hosts": hosts_out, "findings": findings_out}

        finally:
            await sa_engine.dispose()
            try:
                os.unlink(db_path)
            except OSError:
                pass


def main() -> None:
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="ScanR full-featured remote agent")
    parser.add_argument(
        "--server",
        default=os.environ.get("SCANR_SERVER"),
        help="ScanR server URL (or set SCANR_SERVER env var)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("SCANR_TOKEN"),
        help="Agent token (or set SCANR_TOKEN env var)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(os.environ.get("SCANR_POLL_INTERVAL", POLL_INTERVAL)),
        help="Poll interval in seconds",
    )
    args = parser.parse_args()

    if not args.server or not args.token:
        parser.error("--server and --token are required (or set SCANR_SERVER / SCANR_TOKEN)")

    runner = FullAgentRunner(server_url=args.server, token=args.token, poll_interval=args.interval)
    asyncio.run(runner.run())


if __name__ == "__main__":
    main()
