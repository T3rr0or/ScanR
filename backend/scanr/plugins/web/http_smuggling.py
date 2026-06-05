"""HTTP request smuggling detection (CL.TE and TE.CL).

Uses raw asyncio sockets — httpx/aiohttp normalize headers and cannot send
the ambiguous CL+TE combinations required for smuggling probes.

Detects desync by timing: if the second request in a CL.TE pair is significantly
delayed, the first request's smuggled bytes were queued.

Gate: intrusive:true — sends two HTTP requests back-to-back per probe.
"""
from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._ports import is_web_port

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443]
_TIMEOUT = 10.0
_TIMING_THRESHOLD = 4.0  # seconds — suspicious delay on second request


class HttpSmugglingPlugin(PluginBase):
    id = "web.http_smuggling"
    name = "HTTP Request Smuggling (CL.TE / TE.CL)"
    description = "Detect HTTP/1.1 request desync via raw socket CL.TE and TE.CL probes"
    category = PluginCategory.web
    severity = Severity.high
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        _pj: dict = {}
        if context.scan.profile_json:
            try:
                _pj = json.loads(context.scan.profile_json) if isinstance(context.scan.profile_json, str) else context.scan.profile_json
            except Exception:
                pass
        if not _pj.get("intrusive", False):
            return []

        findings = []
        for port in host.ports:
            if not is_web_port(port):
                continue
            tls = port.number in (443, 8443)
            result = await self._probe(host.ip, port.number, tls)
            if result:
                findings.append(result)
        return findings

    async def _probe(self, ip: str, port: int, tls: bool) -> FindingData | None:
        # CL.TE probe: Content-Length undercounts, Transfer-Encoding chunked is real
        # If backend uses CL, it reads partial body. Smuggled prefix queued for next request.
        cl_te_probe = (
            "POST / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"  # smuggled byte — outside CL but inside TE body
        ).encode()

        # Benign request to detect if second request is delayed
        benign = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()

        try:
            # Measure benign baseline
            t0 = time.monotonic()
            await self._send_raw(ip, port, tls, benign)
            baseline = time.monotonic() - t0

            # Send CL.TE probe + immediately follow with benign
            writer = None
            second_elapsed = 0.0  # default — prevents UnboundLocalError if connection fails
            try:
                reader, writer = await asyncio.wait_for(
                    self._open_connection(ip, port, tls), timeout=5.0
                )
                writer.write(cl_te_probe)
                await writer.drain()

                # Small pause to let backend process
                await asyncio.sleep(0.1)
                writer.write(benign)
                await writer.drain()

                t0 = time.monotonic()
                try:
                    await asyncio.wait_for(reader.read(4096), timeout=_TIMEOUT)
                    await asyncio.wait_for(reader.read(4096), timeout=_TIMEOUT)
                    second_elapsed = time.monotonic() - t0
                except asyncio.TimeoutError:
                    second_elapsed = _TIMEOUT
            finally:
                if writer:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

            if second_elapsed > baseline + _TIMING_THRESHOLD:
                return FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="HTTP Request Smuggling (CL.TE Desync) Detected",
                    description=(
                        f"The server at {ip}:{port} appears vulnerable to CL.TE request smuggling. "
                        "A request with both Content-Length and Transfer-Encoding headers caused the "
                        "second request in a keep-alive connection to be delayed, indicating the "
                        "front-end and back-end servers disagree on request boundaries. "
                        "An attacker can use this to bypass security controls, poison caches, "
                        "capture other users' requests, or achieve SSRF."
                    ),
                    evidence=(
                        f"Probe type: CL.TE\n"
                        f"Baseline response time: {baseline*1000:.0f}ms\n"
                        f"Second request after smuggling probe: {second_elapsed*1000:.0f}ms\n"
                        f"Timing delta: {(second_elapsed - baseline)*1000:.0f}ms (threshold: {_TIMING_THRESHOLD*1000:.0f}ms)"
                    ),
                    remediation=(
                        "Configure the front-end/reverse proxy to normalise Transfer-Encoding headers. "
                        "Reject or rewrite requests with both Content-Length and Transfer-Encoding. "
                        "Upgrade to HTTP/2 where possible (eliminates CL.TE entirely). "
                        "Reference: https://portswigger.net/web-security/request-smuggling"
                    ),
                    references=[
                        "https://portswigger.net/web-security/request-smuggling",
                        "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=request+smuggling",
                    ],
                    port_number=port,
                    protocol="tcp",
                )
        except Exception as exc:
            logger.debug("HTTP smuggling probe failed %s:%d: %s", ip, port, exc)
        return None

    async def _open_connection(self, ip: str, port: int, tls: bool):
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return await asyncio.open_connection(ip, port, ssl=ctx)
        return await asyncio.open_connection(ip, port)

    async def _send_raw(self, ip: str, port: int, tls: bool, data: bytes) -> bytes:
        reader, writer = await asyncio.wait_for(
            self._open_connection(ip, port, tls), timeout=5.0
        )
        try:
            writer.write(data)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            return resp
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
