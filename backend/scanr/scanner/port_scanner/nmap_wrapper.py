from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

logger = logging.getLogger(__name__)


class NmapWrapper:
    """Async wrapper around nmap for port scanning and service detection."""

    async def scan_host(
        self,
        ip: str,
        context: "ScanContext",
        known_ports: list[int] | None = None,
    ) -> dict[str, Any] | None:
        """Run nmap on one host, return structured host data or None if down.

        If known_ports is provided (from a prior masscan run), nmap only scans
        those specific ports, which is significantly faster.
        """
        if known_ports:
            port_arg = "-p " + ",".join(str(p) for p in sorted(set(known_ports)))
        else:
            port_arg = context.get_port_range()
        args = f"-sV -O --osscan-guess -T4 {port_arg} --host-timeout 60s"

        # Try SYN scan first (needs root), fallback to TCP connect
        syn_cmd = f"nmap -sS {args} {ip}"
        await context.log.info(f"$ {syn_cmd}", phase="portscan", host=ip)
        try:
            return await self._run_nmap(ip, f"-sS {args}")
        except asyncio.TimeoutError:
            logger.warning("nmap SYN scan timed out for %s", ip)
            return None
        except Exception:
            pass

        tcp_cmd = f"nmap -sT {args} {ip}"
        await context.log.info(f"$ {tcp_cmd} (TCP fallback)", phase="portscan", host=ip)
        try:
            return await self._run_nmap(ip, f"-sT {args}")
        except asyncio.TimeoutError:
            logger.warning("nmap TCP scan timed out for %s", ip)
            return None

    async def _run_nmap(self, ip: str, args: str) -> dict[str, Any] | None:
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, self._nmap_sync, ip, args),
            timeout=90.0,
        )

    def _nmap_sync(self, ip: str, args: str) -> dict[str, Any] | None:
        import nmap

        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments=args)
        except nmap.PortScannerError as exc:
            logger.warning("nmap scan failed for %s: %s", ip, exc)
            return None

        if ip not in nm.all_hosts():
            return None

        host = nm[ip]
        if host.state() != "up":
            return None

        result: dict[str, Any] = {
            "hostname": self._get_hostname(host),
            "mac": host.get("addresses", {}).get("mac"),
            "ports": [],
        }

        # OS fingerprinting
        if "osmatch" in host and host["osmatch"]:
            best = host["osmatch"][0]
            result["os_name"] = best.get("name")
            result["os_accuracy"] = int(best.get("accuracy", 0))
            if best.get("osclass"):
                result["os_family"] = best["osclass"][0].get("osfamily")

        # Ports
        for proto in host.all_protocols():
            for port_num in host[proto].keys():
                port_info = host[proto][port_num]
                port_data: dict[str, Any] = {
                    "number": port_num,
                    "protocol": proto,
                    "state": port_info.get("state", "unknown"),
                    "reason": port_info.get("reason"),
                }

                svc = {
                    "name": port_info.get("name"),
                    "product": port_info.get("product"),
                    "version": port_info.get("version"),
                    "extra_info": port_info.get("extrainfo"),
                    "cpe": " ".join(port_info.get("cpe", "").split()),
                    "tunnel": port_info.get("tunnel"),
                }
                if any(v for v in svc.values()):
                    port_data["service"] = svc

                result["ports"].append(port_data)

        return result

    def _get_hostname(self, host) -> str | None:
        hostnames = host.get("hostnames", [])
        for hn in hostnames:
            if hn.get("name"):
                return hn["name"]
        return None
