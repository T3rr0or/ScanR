"""SIP/VoIP service discovery and enumeration.

Detects SIP services on UDP 5060/5061, enumerates supported methods,
and checks for unauthenticated extension registration.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

SIP_PORTS = [5060, 5061]


class _SipProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self._data: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if not self._data.done():
            self._data.set_result(data)

    def error_received(self, exc):
        if not self._data.done():
            self._data.set_exception(exc)

    async def received(self) -> bytes:
        return await self._data


def _sip_options(ip: str, port: int) -> bytes:
    return (
        f"OPTIONS sip:{ip}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {ip}:{port};branch=z9hG4bK-scanr\r\n"
        f"From: <sip:scanr@{ip}>;tag=scanr\r\n"
        f"To: <sip:{ip}>\r\n"
        f"Call-ID: scanr-probe@{ip}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"Contact: <sip:scanr@{ip}>\r\n"
        f"Accept: application/sdp\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()


def _sip_register(ip: str, port: int) -> bytes:
    return (
        f"REGISTER sip:{ip} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {ip}:{port};branch=z9hG4bK-scanr-reg\r\n"
        f"From: <sip:1000@{ip}>;tag=scanr\r\n"
        f"To: <sip:1000@{ip}>\r\n"
        f"Call-ID: scanr-reg@{ip}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Max-Forwards: 70\r\n"
        f"Contact: <sip:1000@{ip}>\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()


class SipScanPlugin(PluginBase):
    id = "services.sip_scan"
    name = "SIP / VoIP Service Discovery"
    description = "Detect SIP VoIP services, enumerate methods, check for misconfigurations"
    category = PluginCategory.services
    severity = Severity.medium
    ports = SIP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in (SIP_PORTS if self.ports is None else self.ports):
                continue
            result = await self._probe_sip(host.ip, port.number)
            if result:
                findings.extend(result)
        return findings

    async def _probe_sip(self, ip: str, port: int) -> list[FindingData]:
        findings: list[FindingData] = []
        loop = asyncio.get_running_loop()

        # SIP OPTIONS
        resp = await self._udp_send(ip, port, _sip_options(ip, port))
        if resp:
            parsed = self._parse_sip_response(resp.decode("utf-8", errors="replace"))
            if parsed:
                findings.append(self._options_finding(ip, port, parsed))

        # SIP REGISTER (test for unauthenticated registration)
        resp = await self._udp_send(ip, port, _sip_register(ip, port))
        if resp:
            text = resp.decode("utf-8", errors="replace")
            if "200 OK" in text and "401" not in text and "407" not in text:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="SIP Extension Registration Without Authentication",
                    description=(
                        f"SIP server at {ip}:{port} accepted unauthenticated REGISTER. "
                        "Attacker can register arbitrary extensions."
                    ),
                    evidence=f"REGISTER sip:{ip} -> 200 OK\n{text[:500]}",
                    remediation=(
                        "Require authentication for all SIP REGISTER requests. "
                        "Enable SIP over TLS (SIPS) with mutual auth."
                    ),
                    references=[
                        "https://www.voip-info.org/sip-security/",
                        "https://attack.mitre.org/techniques/T1200/",
                    ],
                    port_number=port,
                    protocol="udp",
                ))

        return findings

    async def _udp_send(self, ip: str, port: int, payload: bytes) -> bytes | None:
        loop = asyncio.get_running_loop()
        try:
            _, proto = await loop.create_datagram_endpoint(
                lambda: _SipProtocol(),
                remote_addr=(ip, port),
            )
            proto.transport.sendto(payload)
            try:
                return await asyncio.wait_for(proto.received(), timeout=5.0)
            except asyncio.TimeoutError:
                return None
            finally:
                proto.transport.close()
        except OSError:
            return None

    def _parse_sip_response(self, raw: str) -> dict | None:
        if not raw.startswith("SIP/2.0"):
            return None
        lines = raw.split("\r\n")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
            elif not line.strip():
                break
        return {"status": lines[0], "headers": headers, "raw": raw[:1000]}

    def _options_finding(self, ip: str, port: int, parsed: dict) -> FindingData:
        h = parsed.get("headers", {})
        server = h.get("server", "Unknown")
        allow = h.get("allow", "")
        methods = [m.strip() for m in allow.split(",") if m.strip()] if allow else []

        severity = Severity.info
        if any(m.upper() == "INVITE" for m in methods):
            severity = Severity.medium

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=f"SIP Service — {server}",
            description=(
                f"SIP VoIP service on {ip}:{port}. "
                f"Server: {server}. Methods: {', '.join(methods) or 'not disclosed'}."
            ),
            evidence=f"Status: {parsed['status']}\nServer: {server}\nAllow: {allow}\n{parsed['raw']}",
            remediation="Disable SIP if unused. Require auth; use SIPS (TLS). Restrict by IP.",
            references=[
                "https://www.voip-info.org/sip-security/",
                "https://attack.mitre.org/techniques/T1200/",
            ],
            port_number=port,
            protocol="udp",
        )
