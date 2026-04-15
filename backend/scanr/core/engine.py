from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from scanr.core.context import ScanContext
from scanr.core.plugin_manager import get_enabled_plugins
from scanr.core.rate_limiter import RateLimiter
from scanr.core.result_collector import ResultCollector
from scanr.core.scan_logger import ScanLogger
from scanr.models import Host, Plugin, Scan, Target
from scanr.models.base import new_uuid

logger = logging.getLogger(__name__)


def _plugin_allowed(plugin_id: str, filters: list[str]) -> bool:
    """Return True if plugin_id matches any entry in the profile filter list."""
    for f in filters:
        if f == "*":
            return True
        if f.endswith(".*") and plugin_id.startswith(f[:-1]):
            return True
        if f == plugin_id:
            return True
    return False


class ScanEngine:
    """Orchestrates a complete scan: discovery → ports → fingerprint → plugins."""

    def __init__(self, scan_id: str, db: AsyncSession):
        self.scan_id = scan_id
        self.db = db

    async def run(self) -> None:
        scan_log = ScanLogger(self.scan_id)
        try:
            await self._run(scan_log)
        finally:
            await scan_log.close()

    async def _run(self, scan_log: ScanLogger) -> None:
        await scan_log.info("Scan engine started", phase="engine")

        # Load scan + targets
        result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = result.scalar_one()

        targets_result = await self.db.execute(
            select(Target).where(Target.scan_id == self.scan_id)
        )
        targets = targets_result.scalars().all()

        # Build context
        context = ScanContext(
            scan_id=self.scan_id,
            scan=scan,
            db=self.db,
            profile=scan.profile,
            log=scan_log,
        )

        # Decrypt credentials if provided
        if scan.credential_id:
            cred_result = await self.db.execute(
                select(__import__("scanr.models", fromlist=["Credential"]).Credential)
                .where(__import__("scanr.models", fromlist=["Credential"]).Credential.id == scan.credential_id)
            )
            cred = cred_result.scalar_one_or_none()
            if cred:
                from scanr.credentials.vault import decrypt
                context.credential_data = decrypt(cred.encrypted_data)
                await scan_log.info(f"Credentials loaded: {cred.name}", phase="engine")

        collector = ResultCollector(self.scan_id, self.db, scan_log, user_id=scan.user_id)
        rate_limiter = RateLimiter()

        # Load enabled plugins from DB
        plugin_result = await self.db.execute(select(Plugin).where(Plugin.enabled == True))
        enabled_ids = {p.id for p in plugin_result.scalars().all()}
        plugins = get_enabled_plugins(enabled_ids)

        # Filter plugins by profile_json.plugins list (e.g. ["web.*", "ssl_tls.*"])
        import json as _json
        profile_filter: list[str] | None = None
        if scan.profile_json:
            try:
                pj = _json.loads(scan.profile_json) if isinstance(scan.profile_json, str) else scan.profile_json
                raw = pj.get("plugins", ["*"])
                if raw != ["*"]:
                    profile_filter = raw
            except Exception:
                pass

        if profile_filter:
            plugins = [p for p in plugins if _plugin_allowed(p.id, profile_filter)]

        await scan_log.info(f"Loaded {len(plugins)} plugins (profile filter: {profile_filter or '*'})", phase="engine")

        # Expand all targets to individual IPs/hostnames
        from scanr.utils.ip_utils import expand_targets

        all_targets: list[str] = []
        for target in targets:
            all_targets.extend(expand_targets(target.value))

        scan.hosts_total = len(all_targets)
        await self.db.commit()

        await scan_log.phase_start(
            "discovery",
            f"Host discovery: probing {len(all_targets)} target(s) — profile={scan.profile}",
        )

        # Phase 1: Host discovery
        from scanr.scanner.discovery.ping_sweep import PingSweep
        sweeper = PingSweep()
        live_targets = await sweeper.discover(all_targets, context)

        scan.hosts_up = len(live_targets)
        await self.db.commit()
        await scan_log.phase_done(
            "discovery",
            f"Discovery complete: {len(live_targets)}/{len(all_targets)} hosts up",
        )

        if not live_targets:
            await scan_log.warn("No live hosts found — scan complete", phase="engine")
            return

        await scan_log.phase_start(
            "portscan",
            f"Port scanning {len(live_targets)} host(s) ...",
        )

        # Phase 2+3+4: Per-host port scan + service fingerprint + plugin dispatch
        sem = rate_limiter.host_slot()
        tasks = [
            self._scan_host(ip, context, plugins, collector, sem)
            for ip in live_targets
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for exc in results:
            if isinstance(exc, Exception) and not isinstance(exc, asyncio.CancelledError):
                logger.error("Unhandled host scan error: %s", exc, exc_info=exc)

        await self.db.commit()
        await scan_log.phase_done(
            "engine",
            f"Scan complete — {context.hosts_scanned} hosts scanned, "
            f"{context.findings_count} findings",
        )

    async def _scan_host(
        self,
        ip: str,
        context: ScanContext,
        plugins: list,
        collector: ResultCollector,
        sem: asyncio.Semaphore,
    ) -> None:
        async with sem:
            context.check_cancelled()

            await context.log.info(f"Scanning {ip} ...", phase="portscan", host=ip)

            from scanr.scanner.port_scanner.nmap_wrapper import NmapWrapper

            nmap = NmapWrapper()
            host_data = await nmap.scan_host(ip, context)
            if not host_data:
                await context.log.warn(f"{ip} — no response from nmap", phase="portscan", host=ip)
                return

            open_ports = [p for p in host_data.get("ports", []) if p["state"] == "open"]
            await context.log.info(
                f"{ip} — {len(open_ports)} open port(s): "
                + ", ".join(str(p["number"]) for p in open_ports[:20])
                + ("..." if len(open_ports) > 20 else ""),
                phase="portscan",
                host=ip,
            )

            # Persist host
            host = Host(
                id=new_uuid(),
                scan_id=self.scan_id,
                ip=ip,
                hostname=host_data.get("hostname"),
                mac_address=host_data.get("mac"),
                os_name=host_data.get("os_name"),
                os_accuracy=host_data.get("os_accuracy"),
                status="up",
            )
            self.db.add(host)
            await self.db.flush()

            # Persist ports + services
            from scanr.models import Port, Service

            for p in host_data.get("ports", []):
                port = Port(
                    id=new_uuid(),
                    host_id=host.id,
                    number=p["number"],
                    protocol=p["protocol"],
                    state=p["state"],
                    reason=p.get("reason"),
                    banner=p.get("banner"),
                )
                self.db.add(port)
                await self.db.flush()

                if p.get("service"):
                    svc = p["service"]
                    service = Service(
                        id=new_uuid(),
                        port_id=port.id,
                        name=svc.get("name"),
                        product=svc.get("product"),
                        version=svc.get("version"),
                        extra_info=svc.get("extra_info"),
                        cpe=svc.get("cpe"),
                        tunnel=svc.get("tunnel"),
                    )
                    self.db.add(service)
                    if svc.get("product"):
                        await context.log.debug(
                            f"{ip}:{p['number']} — {svc.get('product','')} {svc.get('version','')}".strip(),
                            phase="fingerprint",
                            host=ip,
                        )

            await self.db.flush()

            # Reload host with eagerly-loaded ports+services so plugins can
            # safely access host.ports without triggering lazy-load (which
            # raises MissingGreenlet in async SQLAlchemy).
            from scanr.models import Port as _Port
            host_result = await self.db.execute(
                select(Host)
                .where(Host.id == host.id)
                .options(selectinload(Host.ports).selectinload(_Port.service))
            )
            host = host_result.scalar_one()

            # Phase 4: Run applicable plugins concurrently
            applicable = [
                pl for pl in plugins
                if pl.ports is None or any(
                    p["number"] in pl.ports and p["state"] == "open"
                    for p in host_data.get("ports", [])
                )
            ]

            if applicable:
                await context.log.info(
                    f"{ip} — running {len(applicable)} plugin(s)",
                    phase="plugin",
                    host=ip,
                )
            plugin_sem = asyncio.Semaphore(20)
            plugin_tasks = [
                self._run_plugin(plugin, context, host, host_data, collector, plugin_sem)
                for plugin in applicable
            ]
            await asyncio.gather(*plugin_tasks, return_exceptions=True)

            await self.db.flush()
            context.hosts_scanned += 1

    async def _run_plugin(self, plugin, context, host, host_data, collector, sem):
        async with sem:
            context.check_cancelled()
            await context.log.debug(
                f"{host.ip} — plugin: {plugin.name}",
                phase="plugin",
                host=host.ip,
                plugin=plugin.id,
            )
            try:
                findings = await plugin.check(context, host)
                for f in findings:
                    await collector.add_finding(host.id, f)
                    await context.log.finding(
                        f.title,
                        f.severity.value,
                        host=host.ip,
                        plugin=plugin.id,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await context.log.warn(
                    f"Plugin {plugin.id} failed on {host.ip}: {exc}",
                    phase="plugin",
                    host=host.ip,
                    plugin=plugin.id,
                )
