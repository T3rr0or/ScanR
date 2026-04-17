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
import shutil
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

logger = logging.getLogger(__name__)


class MasscanWrapper:
    """Run masscan across a list of targets, return open ports per host."""

    # Packets per second — conservative default that won't saturate most networks.
    # Users running against a local LAN can increase this via scan profile.
    DEFAULT_RATE = 1000

    @staticmethod
    def is_available() -> bool:
        return shutil.which("masscan") is not None

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
        target_str = " ".join(targets)
        open_ports: dict[str, list[int]] = {}

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        cmd = [
            "masscan",
            *targets,
            "-p", port_range,
            "--rate", str(effective_rate),
            "--output-format", "json",
            "--output-filename", out_path,
            "--wait", "3",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=3600.0)
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
