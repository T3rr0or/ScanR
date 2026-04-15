"""
ScanR Agent — lightweight polling scanner for internal/firewalled networks.

Requirements: Python 3.10+, httpx (pip install httpx), nmap binary in PATH.

Usage:
    # Download from your ScanR server:
    curl https://your-scanr-server.com/api/v1/agent/script -o scanr_agent.py

    # Run:
    python scanr_agent.py --server https://your-scanr-server.com --token sk_agent_...

The agent:
  1. Authenticates with the ScanR server using its agent token
  2. Polls /api/v1/agent/jobs every POLL_INTERVAL seconds for pending scans
  3. Runs nmap against the assigned targets (must have nmap installed locally)
  4. Posts hosts, ports, services, and findings back to the server
  5. Logs progress to stdout
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("scanr.agent")

POLL_INTERVAL = 30  # seconds
AGENT_VERSION = "0.1.0"


class AgentRunner:
    def __init__(self, server_url: str, token: str):
        self.server_url = server_url.rstrip("/")
        self.headers = {
            "X-Agent-Token": token,
            "User-Agent": f"ScanR-Agent/{AGENT_VERSION}",
        }

    async def run(self) -> None:
        logger.info("ScanR Agent starting — server: %s", self.server_url)
        # Register / heartbeat
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            try:
                r = await client.post(
                    f"{self.server_url}/api/v1/agent/heartbeat",
                    headers=self.headers,
                    json={"version": AGENT_VERSION},
                )
                if r.status_code == 200:
                    logger.info("Agent registered/heartbeat OK")
                else:
                    logger.warning("Heartbeat returned %s: %s", r.status_code, r.text)
            except Exception as e:
                logger.error("Cannot reach server: %s", e)
                sys.exit(1)

        while True:
            try:
                await self._poll_and_run()
            except Exception as exc:
                logger.error("Poll error: %s", exc)
            await asyncio.sleep(POLL_INTERVAL)

    async def _poll_and_run(self) -> None:
        async with httpx.AsyncClient(timeout=60, verify=False) as client:
            r = await client.get(f"{self.server_url}/api/v1/agent/jobs", headers=self.headers)
            if r.status_code != 200:
                logger.debug("No jobs (HTTP %s)", r.status_code)
                return
            jobs = r.json()
            if not jobs:
                return
            logger.info("%d job(s) pending", len(jobs))
            for job in jobs:
                await self._run_job(job, client)

    async def _run_job(self, job: dict, client: httpx.AsyncClient) -> None:
        scan_id = job["scan_id"]
        targets = job["targets"]
        port_range = job.get("port_range", "top-1000")
        logger.info("Job %s — scanning %d target(s)", scan_id, len(targets))

        # Claim the job
        await client.post(
            f"{self.server_url}/api/v1/agent/jobs/{scan_id}/start",
            headers=self.headers,
        )

        try:
            results = await asyncio.to_thread(self._run_nmap, targets, port_range)
            r = await client.post(
                f"{self.server_url}/api/v1/agent/jobs/{scan_id}/results",
                headers=self.headers,
                json=results,
                timeout=120,
            )
            if r.status_code == 200:
                logger.info("Job %s — results submitted (%d hosts)", scan_id, len(results.get("hosts", [])))
            else:
                logger.error("Job %s — results rejected: %s", scan_id, r.text)
        except Exception as exc:
            logger.error("Job %s failed: %s", scan_id, exc)
            await client.post(
                f"{self.server_url}/api/v1/agent/jobs/{scan_id}/fail",
                headers=self.headers,
                json={"error": str(exc)},
            )

    def _run_nmap(self, targets: list[str], port_range: str) -> dict:
        """Run nmap synchronously and parse XML output."""
        target_str = " ".join(targets)

        # Map port_range to nmap flags
        if port_range == "top-1000":
            port_flags = ["--top-ports", "1000"]
        elif port_range == "top-10000":
            port_flags = ["--top-ports", "10000"]
        else:
            port_flags = ["-p", port_range]

        cmd = [
            "nmap", "-sV", "--version-intensity", "5",
            "-oX", "-",          # XML to stdout
            "--open",            # only open ports
            "-T4",               # aggressive timing
        ] + port_flags + targets

        logger.debug("nmap cmd: %s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        if proc.returncode != 0 and not proc.stdout.strip().startswith("<?xml"):
            raise RuntimeError(f"nmap failed: {proc.stderr[:200]}")

        return self._parse_nmap_xml(proc.stdout)

    def _parse_nmap_xml(self, xml_str: str) -> dict:
        root = ET.fromstring(xml_str)
        hosts_out = []
        findings_out = []

        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            if status_el is None or status_el.get("state") != "up":
                continue

            # IP
            ip = ""
            hostname = None
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "ipv4":
                    ip = addr_el.get("addr", "")
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                hn = hostnames_el.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")

            ports_out = []
            ports_el = host_el.find("ports")
            if ports_el:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    portnum = int(port_el.get("portid", 0))
                    proto = port_el.get("protocol", "tcp")
                    svc: dict = {}
                    svc_el = port_el.find("service")
                    if svc_el is not None:
                        svc = {
                            "name": svc_el.get("name"),
                            "product": svc_el.get("product"),
                            "version": svc_el.get("version"),
                            "extra_info": svc_el.get("extrainfo"),
                            "tunnel": svc_el.get("tunnel"),
                        }
                    ports_out.append({"number": portnum, "protocol": proto, "state": "open", "service": svc or None})

                    # Emit an info finding per open port
                    svc_name = svc.get("name") or "unknown"
                    findings_out.append({
                        "host_ip": ip,
                        "plugin_id": "network.open_ports_info",
                        "severity": "info",
                        "title": f"Open Port: {portnum}/{proto} ({svc_name})",
                        "description": f"Port {portnum}/{proto} is open. Service: {svc_name}",
                        "port_number": portnum,
                        "protocol": proto,
                    })

            hosts_out.append({
                "ip": ip,
                "hostname": hostname,
                "status": "up",
                "ports": ports_out,
            })

        return {"hosts": hosts_out, "findings": findings_out}


def main() -> None:
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="ScanR remote agent")
    parser.add_argument("--server", required=True, help="ScanR server URL (e.g. https://scanr.company.com)")
    parser.add_argument("--token", required=True, help="Agent token from ScanR settings")
    parser.add_argument("--interval", type=int, default=POLL_INTERVAL, help="Poll interval in seconds")
    args = parser.parse_args()

    runner = AgentRunner(server_url=args.server, token=args.token)
    asyncio.run(runner.run())


if __name__ == "__main__":
    main()
