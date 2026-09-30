"""masscan wrapper for fast initial port discovery.

masscan is orders of magnitude faster than nmap for discovering which
ports are open across large networks. We use it purely for port discovery
(no service detection), then pass the results to nmap which only has to
run against known-open ports.

Falls back gracefully if masscan is not installed.
"""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
from typing import TYPE_CHECKING

from scanr.scanner.port_scanner.nmap_ports import summarize_port_spec

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

logger = logging.getLogger(__name__)

# "rate: 10.00-kpps, 5.12% done, 0:12:30 remaining, found=47"
_PROGRESS_RE = re.compile(
    r"rate:\s*[\d.]+-kpps,\s*([\d.]+)%\s*done,\s*([\d:]+)\s*remaining,\s*found=(\d+)",
    re.IGNORECASE,
)
# "rate: 0.00-kpps, 100.00% done, waiting -84-secs, found=2"
_WAITING_RE = re.compile(r"done,\s*waiting\s+(-?\d+)-secs", re.IGNORECASE)
# "Discovered open port 22/tcp on 10.0.0.5" (TCP only: nmap follows up on these)
_DISCOVERED_RE = re.compile(r"Discovered open port (\d+)/tcp on (\S+)")


class MasscanWrapper:
    """Run masscan across a list of targets, return open ports per host."""

    # Packets per second. 10 000 pps scans 65535 ports across 254 hosts in ~28 min.
    # Raise via profile_json: {"masscan_rate": 50000} for local LANs.
    DEFAULT_RATE = 10000

    # Seconds masscan waits for late replies after sending its last probe.
    WAIT_SECS = 3
    # masscan 1.3.2 with libpcap 1.10 can finish that wait and then block
    # forever in its receive thread, counting "waiting -N-secs" until a packet
    # happens to arrive. Past this many seconds beyond its own deadline,
    # results are complete and the process is stopped.
    _HANG_GRACE_SECS = 5

    # When the profile requests all ports (-p-), masscan still only sweeps this
    # range for initial discovery. nmap then scans known-open ports per host, so
    # missed exotic ports are caught by nmap's per-host run anyway.
    FULL_RANGE_CAP = "1-10000,20000-20010,27017,6379,5432,3306,1433,5900,5984,5985,5986,8080,8443,8888,9090,9200,9300,10250,2375,2376,623"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("masscan") is not None

    @staticmethod
    def _port_args(port_range: str) -> list[str]:
        """Translate nmap-style port spec to masscan -p args."""
        if port_range.startswith("--top-ports"):
            # masscan has no --top-ports; map to a common-ports list
            try:
                n = int(port_range.split()[-1])
            except ValueError:
                n = 1000
            return ["-p", "1-1024,8080,8443,8888,9090,9200,9300,27017,6379,5432,3306,1433,5900,5985,5986"] if n <= 1000 else ["-p", MasscanWrapper.FULL_RANGE_CAP]
        if port_range in ("-p-", "-p -"):
            return ["-p", "1-65535"]
        if port_range.startswith("-p "):
            return ["-p", port_range[3:].strip()]
        if port_range.startswith("-p"):
            return ["-p", port_range[2:].strip()]
        # bare spec like "80,443" or "1-1024"
        return ["-p", port_range]

    @staticmethod
    def _without_excluded_ports(port_args: list[str], excluded: list[int]) -> list[str]:
        """Remove excluded ports from masscan's explicit ``-p`` value.

        Unlike nmap, masscan has no ``--exclude-ports`` option. Its supported
        exclusion switch is target-only, so passing the nmap flag would abort
        the scan rather than enforce the guardrail. Port sets are bounded at
        65,536 values, making expansion and recompression safe here.
        """
        if not excluded:
            return port_args
        if len(port_args) != 2 or port_args[0] != "-p":
            raise ValueError("unsupported masscan port arguments")

        blocked = set(excluded)
        by_protocol: dict[str, set[int]] = {}
        for raw_token in port_args[1].split(","):
            token = raw_token.strip()
            protocol = ""
            if len(token) > 2 and token[1] == ":" and token[0].upper() in {"T", "U"}:
                protocol, token = token[:2].upper(), token[2:]
            if "-" in token:
                start_text, end_text = token.split("-", 1)
            else:
                start_text = end_text = token
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError(f"invalid masscan port token: {raw_token!r}")
            start, end = int(start_text), int(end_text)
            if start > end or start < 0 or end > 65_535:
                raise ValueError(f"invalid masscan port range: {raw_token!r}")
            by_protocol.setdefault(protocol, set()).update(
                port for port in range(start, end + 1) if port not in blocked
            )

        def compress(ports: set[int]) -> list[str]:
            if not ports:
                return []
            ordered = sorted(ports)
            ranges: list[str] = []
            start = previous = ordered[0]
            for port in ordered[1:]:
                if port == previous + 1:
                    previous = port
                    continue
                ranges.append(str(start) if start == previous else f"{start}-{previous}")
                start = previous = port
            ranges.append(str(start) if start == previous else f"{start}-{previous}")
            return ranges

        allowed = [
            f"{protocol}{value}"
            for protocol, ports in by_protocol.items()
            for value in compress(ports)
        ]
        return ["-p", ",".join(allowed)] if allowed else []

    async def scan(
        self,
        targets: list[str],
        port_range: str,
        context: "ScanContext",
        rate: int | None = None,
    ) -> dict[str, list[int]]:
        """Scan targets for open ports. Returns {ip: [open_port, ...]}."""
        if not targets:
            return {}

        if context.exclusion_policy:
            targets, excluded = await context.exclusion_policy.filter_targets(targets)
            if excluded:
                await context.log.warn(
                    f"masscan skipped {len(excluded)} excluded target(s)",
                    phase="portscan",
                )
        if not targets:
            return {}

        effective_rate = rate or self._rate_from_profile(context)

        excluded_ports = context.excluded_ports()
        port_args = self._without_excluded_ports(self._port_args(port_range), excluded_ports)
        if not port_args:
            await context.log.info(
                "masscan skipped because every requested port is excluded",
                phase="portscan",
            )
            return {}
        # Results are read from stdout as masscan prints them, not from an
        # output file: masscan buffers file output until a clean exit, and
        # some masscan/libpcap builds never exit cleanly (see _HANG_GRACE_SECS).
        cmd = [
            "masscan",
            *targets,
            *port_args,
            "--rate", str(effective_rate),
            "--wait", str(self.WAIT_SECS),
        ]

        target_summary = targets[0] if len(targets) == 1 else f"{targets[0]} … ({len(targets)} hosts)"
        await context.log.info(
            f"$ masscan {target_summary} {summarize_port_spec(' '.join(port_args))} "
            f"--rate {effective_rate} --wait {self.WAIT_SECS}",
            phase="portscan",
        )
        found: dict[str, set[int]] = {}
        proc = None
        stalled = False
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async def _read_stdout() -> None:
                assert proc is not None and proc.stdout is not None
                async for raw in proc.stdout:
                    parsed = self.parse_discovery_line(raw.decode(errors="replace"))
                    if parsed:
                        ip, port = parsed
                        found.setdefault(ip, set()).add(port)

            async def _read_stderr() -> None:
                nonlocal stalled
                assert proc is not None and proc.stderr is not None
                last_pct_logged = -5.0
                wait_logged = False
                pending = ""
                while True:
                    chunk = await proc.stderr.read(4096)
                    if not chunk:
                        break
                    pending += chunk.decode(errors="replace")
                    parts = re.split(r"[\r\n]+", pending)
                    pending = parts.pop() if parts else ""
                    for text in parts:
                        text = text.strip()
                        if not text:
                            continue
                        m = _PROGRESS_RE.search(text)
                        if m:
                            pct, remaining, count = float(m.group(1)), m.group(2), m.group(3)
                            # Emit progress every ~5% to give live feedback without spamming.
                            if pct - last_pct_logged >= 5.0 or (pct >= 99.0 and last_pct_logged < 99.0):
                                last_pct_logged = pct
                                await context.log.info(
                                    f"masscan: {pct:.1f}% done — {count} open port(s) found so far, {remaining} remaining",
                                    phase="portscan",
                                )
                            continue
                        w = _WAITING_RE.search(text)
                        if w:
                            if not wait_logged:
                                wait_logged = True
                                await context.log.info(
                                    f"masscan: sweep sent — waiting {self.WAIT_SECS}s for late replies",
                                    phase="portscan",
                                )
                            if int(w.group(1)) <= -self._HANG_GRACE_SECS and not stalled:
                                stalled = True
                                await context.log.warn(
                                    "masscan finished its sweep but did not exit — stopping it "
                                    "(results already collected)",
                                    phase="portscan",
                                )
                                proc.kill()
                            continue
                        if "Scanning" in text and "hosts" in text:
                            # "Scanning 254 hosts [65535 ports/host]"
                            await context.log.info(f"masscan: {text}", phase="portscan")
                        else:
                            await context.log.debug(f"masscan: {text}", phase="portscan")

            await asyncio.wait_for(
                asyncio.gather(_read_stdout(), _read_stderr(), proc.wait()),
                timeout=3600.0,
            )
            if proc.returncode not in (0, None) and not stalled:
                logger.warning("masscan exited %s", proc.returncode)
        except asyncio.TimeoutError:
            logger.warning("masscan timed out")
        except FileNotFoundError:
            logger.warning("masscan not found")
        except Exception as exc:
            logger.warning("masscan failed: %s", exc)
        finally:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    # Reap the killed process so it doesn't linger as a zombie.
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except Exception as exc:
                    logger.warning("failed to reap masscan: %s", exc)

        open_ports = {ip: sorted(ports) for ip, ports in found.items()}
        logger.info("masscan: %d hosts with open ports", len(open_ports))
        # Emit per-host port summary so console shows live results immediately
        for ip, ports in sorted(open_ports.items()):
            await context.log.info(
                f"{ip} — {len(ports)} open port(s): {', '.join(str(p) for p in ports[:20])}"
                + ("…" if len(ports) > 20 else ""),
                phase="portscan",
            )
        return open_ports

    @staticmethod
    def parse_discovery_line(line: str) -> tuple[str, int] | None:
        """Parse masscan's "Discovered open port 22/tcp on 10.0.0.5" line."""
        m = _DISCOVERED_RE.search(line)
        if not m:
            return None
        return m.group(2), int(m.group(1))

    def _rate_from_profile(self, context: "ScanContext") -> int:
        try:
            return int(context.performance_config().get("masscan_rate") or self.DEFAULT_RATE)
        except Exception:
            return self.DEFAULT_RATE
