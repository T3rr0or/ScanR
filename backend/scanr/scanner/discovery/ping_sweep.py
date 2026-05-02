from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

logger = logging.getLogger(__name__)


class PingSweep:
    """Discover live hosts via TCP connect to common ports (works without root)."""

    PROBE_PORTS = [80, 443, 22, 445, 3389, 8080, 8443, 25, 53, 21, 23, 3306, 5432, 6379, 8888]
    TIMEOUT = 1.0  # per-port timeout; total per-host = TIMEOUT × len(PROBE_PORTS) if all timeout

    async def discover(self, targets: list[str], context: "ScanContext") -> list[str]:
        """Return list of responsive IP/hostname strings."""
        cfg = context.discovery_config()
        if cfg["assume_up"]:
            await context.log.info(
                f"Discovery configured to assume hosts are up: {len(targets)} target(s)",
                phase="discovery",
            )
            return targets
        tasks = [self._probe_host(t, context) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        live = [t for t, r in zip(targets, results) if r is True]
        logger.info("Ping sweep: %d/%d hosts up", len(live), len(targets))
        return live

    async def _probe_host(self, target: str, context: "ScanContext") -> bool:
        context.check_cancelled()
        cfg = context.discovery_config()

        # Try ICMP ping via nmap -sn first (requires privileges on most systems)
        if cfg["icmp"]:
            for _ in range(max(1, cfg["retries"] + 1)):
                try:
                    result = await asyncio.wait_for(
                        self._nmap_ping(target),
                        timeout=5.0,
                    )
                    if result:
                        await context.log.debug(f"{target} — up (nmap ping)", phase="discovery", host=target)
                        return True
                except Exception:
                    pass

        # Fallback: TCP connect probe
        if cfg["tcp"]:
            for _ in range(max(1, cfg["retries"] + 1)):
                for port in self.PROBE_PORTS:
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(target, port),
                            timeout=self.TIMEOUT,
                        )
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                        await context.log.debug(f"{target} — up (TCP:{port})", phase="discovery", host=target)
                        return True
                    except ConnectionRefusedError:
                        # RST received — host is up but port is closed
                        await context.log.debug(f"{target} — up (TCP:{port} refused)", phase="discovery", host=target)
                        return True
                    except OSError:
                        # No route / network unreachable / host unreachable — keep trying other ports
                        continue
                    except asyncio.TimeoutError:
                        continue
        await context.log.debug(f"{target} — no response", phase="discovery", host=target)
        return False

    async def _nmap_ping(self, target: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sn", "-T4", "--host-timeout", "5s", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return b"Host is up" in stdout
