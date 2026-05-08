from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

logger = logging.getLogger(__name__)


class PingSweep:
    """Discover live hosts via TCP connect to common ports (works without root).

    Supports three modes:
      - fast:       ICMP + TCP connect to PROBE_PORTS (current default)
      - aggressive: ICMP + TCP SYN/ACK + UDP nmap ping probes + TCP connect fallback
      - skip:       Assume all hosts are up (handled in engine via discovery_config)
    """

    # Full port list for small ranges / thorough scans
    PROBE_PORTS = [80, 443, 22, 445, 3389, 8080, 8443, 25, 53, 21, 23, 3306, 5432, 6379, 8888]
    # Fallback probe list for large ranges when masscan is unavailable.
    # Covers: web (80/443/8080/8443), SSH (22), Windows (445/3389/135), mail (25),
    # DNS (53), FTP (21), common DB (3306), Telnet (23) — 13 ports vs 3.
    # At 0.5s timeout: 6.5s max per dead host → ~17 min for /16 (vs ~33 min full list).
    PROBE_PORTS_FAST = [80, 443, 22, 445, 3389, 135, 8080, 8443, 25, 53, 21, 23, 3306]
    TIMEOUT = 0.5  # per-port timeout
    TIMEOUT_THOROUGH = 1.0  # used when strategy=="validated"

    # Max concurrent host probes (TCP connect path).
    CONCURRENCY = 500
    # Separate, lower cap for nmap subprocess launches. Each nmap process opens ~4-6 FDs
    # (stdout pipe + internal sockets). 500 concurrent nmap processes = ~3000 extra FDs,
    # which exceeds the default ulimit -n 1024 on many Docker containers.
    NMAP_CONCURRENCY = 50

    async def discover(self, targets: list[str], context: "ScanContext") -> list[str]:
        """Return list of responsive IP/hostname strings."""
        cfg = context.discovery_config()
        if cfg.get("mode") == "skip" or cfg["assume_up"]:
            await context.log.info(
                f"Discovery configured to skip/assume hosts are up: {len(targets)} target(s)",
                phase="discovery",
            )
            return targets

        total = len(targets)
        # Use fast/reduced probe set for large ranges to keep discovery time reasonable.
        # /16 = 65534 hosts: fast (13 ports x 0.5s) → ~17 min; thorough (15 ports x 1s) → ~33 min.
        large_range = total > 1024
        probe_ports = self.PROBE_PORTS_FAST if large_range else self.PROBE_PORTS
        timeout = self.TIMEOUT if large_range else self.TIMEOUT_THOROUGH

        if large_range:
            await context.log.info(
                f"Large range ({total} hosts) -- using fast discovery ({len(probe_ports)} probe ports, {timeout}s timeout)",
                phase="discovery",
            )

        sem = asyncio.Semaphore(self.CONCURRENCY)
        nmap_sem = asyncio.Semaphore(self.NMAP_CONCURRENCY)
        completed = 0
        live: list[str] = []
        log_interval = max(1000, total // 20)  # log every ~5% or every 1000 hosts

        async def _bounded_probe(target: str) -> tuple[str, bool]:
            async with sem:
                result = await self._probe_host(
                    target, context, cfg=cfg,
                    probe_ports=probe_ports, timeout=timeout, nmap_sem=nmap_sem,
                )
                return target, bool(result)

        tasks = [asyncio.create_task(_bounded_probe(t)) for t in targets]

        for coro in asyncio.as_completed(tasks):
            try:
                target, is_up = await coro
            except Exception as exc:
                logger.warning("Unexpected probe error: %s", exc)
                completed += 1
                continue
            completed += 1
            if is_up:
                live.append(target)
            if completed % log_interval == 0 or completed == total:
                await context.log.info(
                    f"Discovery progress: {completed}/{total} probed, {len(live)} up so far",
                    phase="discovery",
                )

        logger.info("Ping sweep: %d/%d hosts up", len(live), total)
        return live

    async def _probe_host(
        self,
        target: str,
        context: "ScanContext",
        cfg: dict | None = None,
        probe_ports: list[int] | None = None,
        timeout: float | None = None,
        nmap_sem: asyncio.Semaphore | None = None,
    ) -> bool:
        context.check_cancelled()
        if cfg is None:
            cfg = context.discovery_config()
        mode: str = cfg.get("mode", "fast")
        retries = max(1, cfg["retries"] + 1)  # retries = extra attempts; +1 = total runs
        ports = probe_ports if probe_ports is not None else self.PROBE_PORTS
        t = timeout if timeout is not None else self.TIMEOUT

        # Aggressive mode: use nmap multi-probe (-PS, -PA, -PU) for best detection
        if mode == "aggressive":
            for _ in range(retries):
                if await self._nmap_probe(target, aggressive=True, nmap_sem=nmap_sem, context=context):
                    return True

            # Fall back to TCP connect probe if nmap aggressive did not find host
            if cfg.get("tcp", True):
                for _ in range(retries):
                    for port in ports:
                        if await self._tcp_probe(target, port, t, context):
                            return True

            await context.log.debug(f"{target} -- no response", phase="discovery", host=target)
            return False

        # Fast mode (default): ICMP + TCP connect probe
        if cfg["icmp"]:
            for _ in range(retries):
                if await self._nmap_probe(target, aggressive=False, nmap_sem=nmap_sem, context=context):
                    return True

        # TCP connect probe
        if cfg["tcp"]:
            for _ in range(retries):
                for port in ports:
                    if await self._tcp_probe(target, port, t, context):
                        return True

        await context.log.debug(f"{target} -- no response", phase="discovery", host=target)
        return False

    async def _nmap_probe(
        self,
        target: str,
        aggressive: bool,
        nmap_sem: asyncio.Semaphore | None,
        context: "ScanContext",
    ) -> bool:
        """Run nmap ping probe with subprocess concurrency cap. Handles EMFILE gracefully."""
        import errno as _errno
        sem = nmap_sem or asyncio.Semaphore(self.NMAP_CONCURRENCY)
        try:
            async with sem:
                coro = self._nmap_aggressive_ping(target) if aggressive else self._nmap_ping(target)
                result = await asyncio.wait_for(coro, timeout=8.0 if aggressive else 5.0)
            if result:
                label = "aggressive nmap ping" if aggressive else "nmap ping"
                await context.log.debug(f"{target} -- up ({label})", phase="discovery", host=target)
                return True
        except OSError as exc:
            if exc.errno in (_errno.EMFILE, _errno.ENFILE):
                logger.warning("nmap subprocess skipped for %s: FD exhaustion (EMFILE)", target)
        except Exception:
            pass
        return False

    async def _tcp_probe(self, target: str, port: int, timeout: float, context: "ScanContext") -> bool:
        """Attempt TCP connect to target:port. Returns True if host is up. Retries on EMFILE."""
        import errno as _errno
        for _attempt in range(3):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                await context.log.debug(f"{target} -- up (TCP:{port})", phase="discovery", host=target)
                return True
            except ConnectionRefusedError:
                # RST received — host is up but port is closed
                await context.log.debug(f"{target} -- up (TCP:{port} refused)", phase="discovery", host=target)
                return True
            except OSError as exc:
                if exc.errno in (_errno.EMFILE, _errno.ENFILE):
                    # Local FD exhaustion — retry same port after brief wait
                    await asyncio.sleep(0.05 * (_attempt + 1))
                    continue
                return False  # no route / network unreachable — skip to next port
            except asyncio.TimeoutError:
                return False  # host silent on this port — skip to next port
        return False

    async def _nmap_ping(self, target: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sn", "-T4", "--host-timeout", "5s", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return b"Host is up" in stdout

    async def _nmap_aggressive_ping(self, target: str) -> bool:
        """Aggressive nmap ping using TCP SYN, TCP ACK, and UDP probes."""
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sn", "-PS80,443,22,445,3389,8080", "-PA80,443,22,445",
            "-PU53,161,123,137", "-T4", "--host-timeout", "8s", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return b"Host is up" in stdout
