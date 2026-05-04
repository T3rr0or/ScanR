from __future__ import annotations

import asyncio
import logging
import os
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

        When multiple scanners are selected (e.g. tcp_connect + udp), runs each
        scan type sequentially and merges results — ports are deduplicated by
        (number, protocol). OS fingerprint data comes from whichever scan
        produced it.
        """
        if known_ports:
            port_arg = "-p " + ",".join(str(p) for p in sorted(set(known_ports)))
        else:
            port_arg = context.get_port_range()
        port_cfg = context.port_scanning_config()
        perf_cfg = context.performance_config()
        service_detection = context.profile_json().get("enumeration", {}).get("service_detection", True)
        ping_arg = "-Pn" if port_cfg["firewall_strategy"] == "skip_ping" else ""
        discovery_cfg = context.discovery_config()
        if discovery_cfg.get("mode") == "skip" or discovery_cfg.get("assume_up"):
            ping_arg = "-Pn"
        host_timeout = int(perf_cfg.get("timeout") or 60)
        euid = os.geteuid()

        scanners: list[str] = port_cfg.get("scanners", ["tcp_connect"])
        merged: dict[str, Any] | None = None

        for scanner in scanners:
            args: str
            if scanner == "udp":
                args = f"-sU -sV -T4 {ping_arg} {port_arg} --host-timeout {host_timeout}s".strip()
            elif scanner == "tcp_connect":
                service = "-sV" if service_detection else ""
                args = f"-sT {service} -T4 {ping_arg} {port_arg} --host-timeout {host_timeout}s".strip()
            else:
                service = "-sV" if service_detection else ""
                args = f"-sS {service} -O --osscan-guess -T4 {ping_arg} {port_arg} --host-timeout {host_timeout}s".strip()

            cmd = f"nmap {args} {ip}"
            await context.log.info(f"$ {cmd}", phase="portscan", host=ip)
            try:
                result = await self._run_nmap(ip, args)
            except asyncio.TimeoutError:
                logger.warning("nmap %s scan timed out for %s", scanner, ip)
                if scanner == "syn":
                    # Fallback to TCP connect on SYN failure
                    service = "-sV" if service_detection else ""
                    fallback_args = f"-sT {service} -T4 {ping_arg} {port_arg} --host-timeout {host_timeout}s".strip()
                    await context.log.info(f"$ nmap {fallback_args} {ip} (TCP fallback)", phase="portscan", host=ip)
                    try:
                        result = await self._run_nmap(ip, fallback_args)
                    except asyncio.TimeoutError:
                        logger.warning("nmap TCP fallback timed out for %s", ip)
                        continue
                    except Exception:
                        logger.warning("nmap TCP fallback failed for %s", ip)
                        continue
                else:
                    continue
            except Exception:
                logger.warning("nmap %s scan failed for %s", scanner, ip)
                continue

            if result is None:
                continue

            # Merge results — deduplicate ports by (number, protocol)
            if merged is None:
                merged = result
            else:
                seen = {(p["number"], p["protocol"]) for p in merged["ports"]}
                for p in result.get("ports", []):
                    key = (p["number"], p["protocol"])
                    if key not in seen:
                        merged["ports"].append(p)
                        seen.add(key)
                # Carry over OS data if not already set
                if not merged.get("os_name") and result.get("os_name"):
                    merged["os_name"] = result["os_name"]
                    merged["os_accuracy"] = result.get("os_accuracy", 0)
                    merged["os_family"] = result.get("os_family")
                # Carry over hostname if not already set
                if not merged.get("hostname") and result.get("hostname"):
                    merged["hostname"] = result["hostname"]

        return merged

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
            raise

        scanned_hosts = nm.all_hosts()
        if not scanned_hosts:
            return None

        scanned_host = ip if ip in scanned_hosts else scanned_hosts[0]
        host = nm[scanned_host]
        if host.state() != "up":
            return None

        addresses = host.get("addresses", {})
        result: dict[str, Any] = {
            "address": addresses.get("ipv4") or addresses.get("ipv6") or scanned_host,
            "target": ip,
            "hostname": self._get_hostname(host),
            "mac": addresses.get("mac"),
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
