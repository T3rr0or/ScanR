"""masscan wrapper for fast initial port discovery.

masscan is orders of magnitude faster than nmap for discovering which
ports are open across large networks. We use it purely for port discovery
(no service detection), then pass the results to nmap which only has to
run against known-open ports.

Falls back gracefully if masscan is not installed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

logger = logging.getLogger(__name__)


class MasscanWrapper:
    """Run masscan across a list of targets, return open ports per host."""

    # Packets per second. 10 000 pps scans 65535 ports across 254 hosts in ~28 min.
    # Raise via profile_json: {"masscan_rate": 50000} for local LANs.
    DEFAULT_RATE = 10000

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
            return ["-p", "1-1024,8080,8443,8888,9090,9200,9300,27017,6379,5432,3306,1433,5900,5985,5986"] if n <= 1000 else ["-p", "1-65535"]
        if port_range in ("-p-", "-p -"):
            return ["-p", MasscanWrapper.FULL_RANGE_CAP]
        if port_range.startswith("-p "):
            return ["-p", port_range[3:].strip()]
        if port_range.startswith("-p"):
            return ["-p", port_range[2:].strip()]
        # bare spec like "80,443" or "1-1024"
        return ["-p", port_range]

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

        effective_rate = rate or self._rate_from_profile(context)
        open_ports: dict[str, list[int]] = {}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        port_args = self._port_args(port_range)
        cmd = [
            "masscan",
            *targets,
            *port_args,
            "--rate", str(effective_rate),
            "--output-format", "json",
            "--output-filename", out_path,
            "--wait", "3",
        ]

        target_summary = targets[0] if len(targets) == 1 else f"{targets[0]} … ({len(targets)} hosts)"
        await context.log.info(
            f"$ masscan {target_summary} {' '.join(port_args)} --rate {effective_rate} --output-format json --wait 3",
            phase="portscan",
        )
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )

            # Regex to parse masscan progress lines:
            # "rate: 10.00-kpps, 5.12% done, 0:12:30 remaining, found=47"
            _progress_re = re.compile(
                r"rate:\s*([\d.]+)-kpps,\s*([\d.]+)%\s*done,\s*([\d:]+)\s*remaining,\s*found=(\d+)",
                re.IGNORECASE,
            )
            _last_pct_logged = [-5.0]  # emit at most every 5%

            async def _stream_stderr() -> bytes:
                chunks: list[bytes] = []
                assert proc is not None
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    chunks.append(line)
                    text = line.decode(errors="replace").rstrip()
                    if not text:
                        continue

                    m = _progress_re.search(text)
                    if m:
                        rate_kpps, pct, remaining, found = m.group(1), float(m.group(2)), m.group(3), m.group(4)
                        # Emit progress every ~5% to give live feedback without spamming
                        if pct - _last_pct_logged[0] >= 5.0 or pct >= 99.0:
                            _last_pct_logged[0] = pct
                            await context.log.info(
                                f"masscan: {pct:.1f}% done — {found} open port(s) found so far, {remaining} remaining",
                                phase="portscan",
                            )
                    elif "Scanning" in text and "hosts" in text:
                        # "Scanning 254 hosts [65535 ports/host]"
                        await context.log.info(f"masscan: {text}", phase="portscan")
                    else:
                        await context.log.debug(f"masscan: {text}", phase="portscan")
                return b"".join(chunks)

            stderr_bytes, _ = await asyncio.wait_for(
                asyncio.gather(_stream_stderr(), proc.wait()),
                timeout=3600.0,
            )
            stderr = stderr_bytes
            if proc.returncode not in (0, None):
                logger.warning("masscan exited %s: %s", proc.returncode, stderr.decode()[:200])

            open_ports = self._parse_json(out_path)
        except asyncio.TimeoutError:
            logger.warning("masscan timed out")
            if proc:
                proc.kill()
        except FileNotFoundError:
            logger.warning("masscan not found")
        except Exception as exc:
            logger.warning("masscan failed: %s", exc)
        finally:
            import os
            try:
                os.unlink(out_path)
            except OSError:
                pass

        logger.info("masscan: %d hosts with open ports", len(open_ports))
        # Emit per-host port summary so console shows live results immediately
        for ip, ports in sorted(open_ports.items()):
            await context.log.info(
                f"{ip} — {len(ports)} open port(s): {', '.join(str(p) for p in sorted(ports)[:20])}"
                + ("…" if len(ports) > 20 else ""),
                phase="portscan",
            )
        return open_ports

    def _parse_json(self, path: str) -> dict[str, list[int]]:
        result: dict[str, list[int]] = {}
        try:
            with open(path) as f:
                content = f.read().strip()
            if not content:
                return result
            # masscan outputs JSONL (one object per line) or a JSON array with trailing comma
            # Try array parse first, then fall back to JSONL
            content = content.rstrip(",").strip()
            if content.startswith("["):
                records = json.loads(content)
            else:
                # JSONL: parse each non-empty line as a separate JSON object
                records = []
                for line in content.splitlines():
                    line = line.strip().rstrip(",")
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            for rec in records:
                ip = rec.get("ip")
                for port_info in rec.get("ports", []):
                    if port_info.get("status") == "open":
                        port_num = port_info.get("port")
                        if ip and port_num is not None:
                            result.setdefault(ip, []).append(int(port_num))
        except Exception as exc:
            logger.debug("masscan JSON parse error: %s", exc)
        return result

    def _rate_from_profile(self, context: "ScanContext") -> int:
        try:
            import json as _json
            pj = context.scan.profile_json
            if isinstance(pj, str):
                pj = _json.loads(pj)
            return int(pj.get("masscan_rate", self.DEFAULT_RATE))
        except Exception:
            return self.DEFAULT_RATE
