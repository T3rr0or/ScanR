from __future__ import annotations

import asyncio
import functools
import logging
import os
import shutil
import struct
from typing import TYPE_CHECKING, Any

from scanr.scanner.port_scanner.nmap_ports import summarize_port_spec

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

logger = logging.getLogger(__name__)

class NmapHostTimeout(Exception):
    """nmap hit --host-timeout and discarded everything it found on the host."""


_CAP_NET_RAW = 13
_VFS_CAP_FLAGS_EFFECTIVE = 0x000001


def _proc_status_field(name: str) -> str | None:
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                key, _, value = line.partition(":")
                if key == name:
                    return value.strip()
    except OSError:
        pass
    return None


def _has_cap_net_raw(mask_hex: str | None) -> bool:
    try:
        return bool(int(mask_hex or "0", 16) & (1 << _CAP_NET_RAW))
    except ValueError:
        return False


@functools.lru_cache(maxsize=1)
def nmap_can_use_raw_sockets() -> bool:
    """Whether nmap can open raw sockets (needed for -sS, -sU and -O).

    Root can when CAP_NET_RAW is effective. A non-root worker can only through
    a file capability on the nmap binary, which the kernel honours only when
    CAP_NET_RAW is in the bounding set and no_new_privs is unset. nmap does not
    detect file capabilities itself: it must be told with --privileged.
    """
    if os.geteuid() == 0:
        return _has_cap_net_raw(_proc_status_field("CapEff"))
    path = shutil.which("nmap")
    if not path:
        return False
    try:
        xattr = os.getxattr(path, "security.capability")
        magic_etc, permitted = struct.unpack_from("<II", xattr)
    except (OSError, struct.error):
        return False
    if not (magic_etc & _VFS_CAP_FLAGS_EFFECTIVE and permitted & (1 << _CAP_NET_RAW)):
        return False
    if _proc_status_field("NoNewPrivs") not in (None, "0"):
        return False
    return _has_cap_net_raw(_proc_status_field("CapBnd"))


def nmap_privilege_args() -> str:
    """Extra nmap flags for raw-socket scans, or "" when running as root."""
    return "--privileged" if os.geteuid() != 0 else ""


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
        if await context.target_is_excluded(ip):
            await context.log.warn(
                f"Skipping nmap for excluded target {ip}", phase="portscan", host=ip
            )
            return None

        excluded_ports = context.excluded_ports()
        if known_ports is not None:
            allowed_known_ports = sorted({p for p in known_ports if p not in excluded_ports})
            if not allowed_known_ports:
                # The host was already observed during discovery, but there is no
                # operator-approved port left for nmap to touch.
                return {"address": ip, "target": ip, "hostname": None, "ports": []}
            port_arg = "-p " + ",".join(str(p) for p in allowed_known_ports)
        else:
            port_arg = context.get_port_range()
        if excluded_ports:
            port_arg += " --exclude-ports " + ",".join(map(str, excluded_ports))
        port_cfg = context.port_scanning_config()
        perf_cfg = context.performance_config()
        service_detection = context.profile_json().get("enumeration", {}).get("service_detection", True)
        ping_arg = "-Pn" if port_cfg["firewall_strategy"] == "skip_ping" else ""
        discovery_cfg = context.discovery_config()
        if discovery_cfg.get("mode") == "skip" or discovery_cfg.get("assume_up"):
            ping_arg = "-Pn"
        host_timeout = int(perf_cfg.get("timeout") or 60)
        scanners: list[str] = port_cfg.get("scanners", ["tcp_connect"])
        merged: dict[str, Any] | None = None

        raw_ok = nmap_can_use_raw_sockets()
        priv = nmap_privilege_args() if raw_ok else ""
        service = "-sV" if service_detection else ""
        connect_args = f"-sT {service} -T4 {ping_arg} {port_arg} --host-timeout {host_timeout}s"
        # Only an error on every attempted scan type counts as a failed host.
        # A scan type that ran and saw nothing is a valid (empty) answer.
        errors: list[str] = []
        any_scan_ran = False

        effective: list[str] = []
        for scanner in scanners:
            if scanner in ("udp", "syn") and not raw_ok:
                if scanner == "udp":
                    # There is no unprivileged UDP scan to fall back to.
                    await context.log.warn(
                        "UDP scan skipped: nmap has no raw-socket access in this worker",
                        phase="portscan", host=ip,
                    )
                    continue
                # A SYN scan without raw sockets aborts outright; TCP connect
                # finds the same open ports without them.
                scanner = "tcp_connect"
            if scanner not in effective:
                effective.append(scanner)

        connect_done = False
        for scanner in effective:
            if scanner == "tcp_connect" and connect_done:
                continue
            if scanner == "udp":
                args = f"{priv} -sU -sV -T4 {ping_arg} {port_arg} --host-timeout {host_timeout}s"
            elif scanner == "tcp_connect":
                args = connect_args
            else:
                args = (
                    f"{priv} -sS {service} -O --osscan-guess -T4 {ping_arg} {port_arg} "
                    f"--host-timeout {host_timeout}s"
                )
            args = " ".join(args.split())

            await context.log.info(f"$ nmap {summarize_port_spec(args)} {ip}", phase="portscan", host=ip)
            try:
                result = await self._run_with_detection_fallback(ip, args, context)
            except Exception as exc:
                reason = _nmap_error(exc)
                logger.warning("nmap %s scan failed for %s: %s", scanner, ip, reason)
                errors.append(f"nmap {scanner} scan {reason}")
                if scanner != "syn":
                    continue
                # Any SYN failure (timeout, privileges, raw-socket errors)
                # falls back to TCP connect rather than dropping the host.
                fallback_args = " ".join(connect_args.split())
                await context.log.info(
                    f"$ nmap {summarize_port_spec(fallback_args)} {ip} (TCP fallback)", phase="portscan", host=ip
                )
                connect_done = True
                try:
                    result = await self._run_with_detection_fallback(ip, fallback_args, context)
                except Exception as fb_exc:
                    reason = _nmap_error(fb_exc)
                    logger.warning("nmap TCP fallback failed for %s: %s", ip, reason)
                    errors.append(f"nmap TCP fallback {reason}")
                    continue
            any_scan_ran = True
            if scanner == "tcp_connect":
                connect_done = True

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

        if not any_scan_ran and errors:
            context.port_scan_errors[ip] = "; ".join(errors)
        return merged

    async def _run_with_detection_fallback(
        self, ip: str, args: str, context: "ScanContext"
    ) -> dict[str, Any] | None:
        """Run nmap; if version/OS probing blows the host timeout, keep the ports.

        nmap discards every open port on a host that exceeds --host-timeout,
        and -sV alone can take ~55s on a service it cannot identify (ArangoDB
        on 8529). Losing the host silently is worse than losing its versions.
        """
        try:
            return await self._run_nmap(ip, args)
        except NmapHostTimeout:
            detection = {"-sV", "-O", "--osscan-guess"}
            tokens = args.split()
            if not detection & set(tokens):
                raise
            await context.log.warn(
                f"{ip} — service/OS detection exceeded the host timeout; "
                "rescanning for open ports without version detection",
                phase="portscan", host=ip,
            )
            return await self._run_nmap(ip, " ".join(t for t in tokens if t not in detection))

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

        output = nm.get_nmap_last_output()
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        if 'timedout="true"' in (output or ""):
            raise NmapHostTimeout(ip)

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


def _nmap_error(exc: Exception) -> str:
    """First meaningful line of an nmap error, for the scan console."""
    if isinstance(exc, asyncio.TimeoutError):
        return "timed out"
    if isinstance(exc, NmapHostTimeout):
        return "exceeded the host timeout"
    for line in str(exc).strip().strip("'\"").replace("\\n", "\n").splitlines():
        line = line.strip().strip("'\"")
        if line and line != "QUITTING!":
            return f"failed: {line}"
    return f"failed: {type(exc).__name__}"
