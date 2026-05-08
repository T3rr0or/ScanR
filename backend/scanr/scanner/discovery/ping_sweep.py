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

    # Max concurrent host probes. Prevents FD exhaustion on large CIDR ranges (/16 = 65534 hosts).
    # Each slot opens at most 1 TCP connection at a time, so this bounds open FDs.
    CONCURRENCY = 500

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
        # /16 = 65534 hosts: fast (3 ports x 0.5s) ~4 min; thorough (15 ports x 1s) ~33 min.
        large_range = total > 1024
        probe_ports = self.PROBE_PORTS_FAST if large_range else self.PROBE_PORTS
        timeout = self.TIMEOUT if large_range else self.TIMEOUT_THOROUGH

        if large_range:
            await context.log.info(
                f"Large range ({total} hosts) -- using fast discovery ({len(probe_ports)} probe ports, {timeout}s timeout)",
                phase="discovery",
            )

        sem = asyncio.Semaphore(self.CONCURRENCY)
        completed = 0
        live: list[str] = []
        log_interval = max(1000, total // 20)  # log every ~5% or every 1000 hosts

        async def _bounded_probe(target: str) -> tuple[str, bool]:
            async with sem:
                result = await self._probe_host(target, context, probe_ports=probe_ports, timeout=timeout)
                return target, result is True

        tasks = [asyncio.ensure_future(_bounded_probe(t)) for t in targets]

        for coro in asyncio.as_completed(tasks):
            target, is_up = await coro
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
        probe_ports: list[int] | None = None,
        timeout: float | None = None,
    ) -> bool:
        context.check_cancelled()
        cfg = context.discovery_config()
        mode: str = cfg.get("mode", "fast")
        retries = max(1, cfg["retries"] + 1)
        ports = probe_ports if probe_ports is not None else self.PROBE_PORTS
        t = timeout if timeout is not None else self.TIMEOUT

        # Aggressive mode: use nmap multi-probe (-PS, -PA, -PU) for best detection
        if mode == "aggressive":
            for _ in range(retries):
                try:
                    result = await asyncio.wait_for(
                        self._nmap_aggressive_ping(target),
                        timeout=8.0,
                    )
                    if result:
                        await context.log.debug(f"{target} -- up (aggressive nmap ping)", phase="discovery", host=target)
                        return True
                except Exception:
                    pass

            # Fall back to TCP connect probe if nmap aggressive did not find host
            if cfg.get("tcp", True):
                for _ in range(retries):
                    for port in ports:
                        try:
                            _, writer = await asyncio.wait_for(
                                asyncio.open_connection(target, port),
                                timeout=t,
                            )
                            writer.close()
                            try:
                                await writer.wait_closed()
                            except Exception:
                                pass
                            await context.log.debug(f"{target} -- up (TCP:{port})", phase="discovery", host=target)
                            return True
                        except ConnectionRefusedError:
                            await context.log.debug(f"{target} -- up (TCP:{port} refused)", phase="discovery", host=target)
                            return True
                        except OSError as exc:
                            import errno as _errno
                            if exc.errno in (_errno.EMFILE, _errno.ENFILE):
                                await asyncio.sleep(0.05)
                            continue
                        except asyncio.TimeoutError:
                            continue

            await context.log.debug(f"{target} -- no response", phase="discovery", host=target)
            return False

        # Fast mode (default): ICMP + TCP connect probe
        if cfg["icmp"]:
            for _ in range(retries):
                try:
                    result = await asyncio.wait_for(
                        self._nmap_ping(target),
                        timeout=5.0,
                    )
                    if result:
                        await context.log.debug(f"{target} -- up (nmap ping)", phase="discovery", host=target)
                        return True
                except Exception:
                    pass

        # TCP connect probe
        if cfg["tcp"]:
            for _ in range(retries):
                for port in ports:
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(target, port),
                            timeout=t,
                        )
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                        await context.log.debug(f"{target} -- up (TCP:{port})", phase="discovery", host=target)
                        return True
                    except ConnectionRefusedError:
                        # RST received -- host is up but port is closed
                        await context.log.debug(f"{target} -- up (TCP:{port} refused)", phase="discovery", host=target)
                        return True
                    except OSError as exc:
                        import errno as _errno
                        if exc.errno in (_errno.EMFILE, _errno.ENFILE):
                            # Local FD exhaustion -- not the remote host's fault; wait briefly and retry
                            await asyncio.sleep(0.05)
                        # No route / network unreachable / host unreachable -- try next port
                        continue
                    except asyncio.TimeoutError:
                        continue

        await context.log.debug(f"{target} -- no response", phase="discovery", host=target)
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
