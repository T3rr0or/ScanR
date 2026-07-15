"""Detect common services on non-standard ports (definitive-signal fallback).

Most service plugins are locked to fixed ports (FTP 21, MySQL 3306, Redis 6379,
RDP 3389, …), so the service is invisible when it runs on an unusual port. This
plugin probes every open, otherwise-unidentified TCP port and confirms a service
only on an unambiguous protocol signal — never a guess:

Passive (server speaks first):
- VNC   : ``RFB 00x.00y`` protocol magic
- SMTP  : ``ESMTP`` / ``220 … smtp`` greeting
- FTP   : ``220`` greeting naming a known FTP daemon or containing "ftp"
- MySQL : the binary server-greeting packet (protocol v10 + version string)

Active (single crafted handshake, client speaks first):
- PostgreSQL : ``SSLRequest`` → single-byte ``S``/``N`` reply
- Redis      : ``PING`` → ``+PONG`` (unauth, flagged high) / ``-NOAUTH``
- RDP        : X.224 Connection Request → TPKT Connection Confirm
- MongoDB    : OP_QUERY ``isMaster`` → a valid OP_REPLY/OP_MSG

Every matcher is strict, so unrelated services never produce a finding.
"""
from __future__ import annotations

import asyncio
import logging
import re
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# Ports already handled by the dedicated service/SSH/telnet plugins.
_COVERED_PORTS = {
    21, 22, 23, 25, 139, 161, 389, 445, 465, 587, 636, 993, 995, 1433, 2022,
    2222, 2323, 2525, 3268, 3269, 3306, 3389, 5432, 5900, 5901, 5902, 5903,
    5985, 5986, 6379, 6380, 9200, 11211, 22222, 27017, 27018, 27019,
}
_MAX_CANDIDATES = 150
_MAX_ACTIVE_PROBES = 300   # shared budget for crafted handshakes across the host
_CONCURRENCY = 20

_TARGET_HINTS = ("ftp", "smtp", "vnc", "redis", "mysql", "postgres", "mongo", "rdp", "ms-wbt")

# ── crafted probe payloads ──────────────────────────────────────────────────
_PG_SSLREQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
_REDIS_PING = b"*1\r\n$4\r\nPING\r\n"
_RDP_CR = bytes([
    0x03, 0x00, 0x00, 0x13,              # TPKT: v3, len 19
    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,  # X.224 Connection Request
    0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,  # RDP_NEG_REQ
])


def _mongo_ismaster() -> bytes:
    bson = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"  # {isMaster: 1}
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, 1) + bson
    header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)  # OP_QUERY
    return header + body


_MONGO_ISMASTER = _mongo_ismaster()


# ── strict matchers (pure, on raw bytes) ────────────────────────────────────
def _classify_banner(banner: str | None) -> str | None:
    """VNC/SMTP/FTP from a definitive text-banner signature, else None."""
    if not banner:
        return None
    b = banner.strip()
    low = b.lower()
    if b.startswith("RFB 00"):
        return "vnc"
    if "esmtp" in low or (b.startswith("220") and "smtp" in low):
        return "smtp"
    if any(d in low for d in ("vsftpd", "proftpd", "filezilla", "pure-ftpd", "microsoft ftp")) or (
        b.startswith("220") and "ftp" in low
    ):
        return "ftp"
    return None


def _match_mysql(data: bytes) -> str | None:
    """MySQL server greeting: [len(3)][seq=0][proto=0x0a][version…\\x00]. Returns version."""
    if len(data) < 6 or data[3] != 0x00 or data[4] != 0x0A:
        return None
    end = data.find(b"\x00", 5)
    if end == -1:
        return None
    ver = data[5:end].decode(errors="replace")
    return ver if re.match(r"\d+\.\d+", ver) else None


def _match_postgres(data: bytes) -> bool:
    return data in (b"S", b"N")  # SSLRequest reply is exactly one byte


def _match_rdp(data: bytes) -> bool:
    return len(data) >= 6 and data[:2] == b"\x03\x00" and data[5] == 0xD0  # TPKT + X.224 CC


def _match_mongo(data: bytes) -> bool:
    if len(data) < 16:
        return False
    return int.from_bytes(data[12:16], "little") in (1, 2013)  # OP_REPLY / OP_MSG


class ServiceFallbackPlugin(PluginBase):
    id = "services.service_fallback"
    name = "Service on Non-Standard Port"
    description = "Detect FTP/SMTP/VNC/MySQL/PostgreSQL/Redis/MongoDB/RDP on non-standard ports"
    category = PluginCategory.services
    severity = Severity.low
    ports = None  # all ports

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        candidates: list[int] = []
        for p in host.ports:
            if p.state != "open" or p.number in _COVERED_PORTS:
                continue
            svc = (p.service.name.lower() if p.service and p.service.name else "")
            if svc and not any(h in svc for h in _TARGET_HINTS):
                continue
            candidates.append(p.number)
            if len(candidates) >= _MAX_CANDIDATES:
                break
        if not candidates:
            return []

        sem = asyncio.Semaphore(_CONCURRENCY)
        active_budget = [_MAX_ACTIVE_PROBES]

        async def probe(port: int) -> list[FindingData]:
            async with sem:
                return await self._probe_port(host.ip, port, active_budget)

        results = await asyncio.gather(*[probe(p) for p in candidates])
        return [f for group in results for f in group]

    async def _probe_port(self, ip: str, port: int, budget: list[int]) -> list[FindingData]:
        raw = await self._read_passive(ip, port)
        if raw:
            kind = _classify_banner(raw.decode(errors="replace"))
            if kind:
                return self._banner_findings(kind, ip, port, raw.decode(errors="replace").strip())
            ver = _match_mysql(raw)
            if ver:
                return self._db_findings("mysql", ip, port, f"MySQL {ver}")
            return []  # got data but nothing we recognise — don't guess
        # Bannerless: try crafted handshakes within the shared budget.
        for name, payload, matcher in (
            ("postgresql", _PG_SSLREQUEST, _match_postgres),
            ("mongodb", _MONGO_ISMASTER, _match_mongo),
            ("rdp", _RDP_CR, _match_rdp),
        ):
            if budget[0] <= 0:
                break
            budget[0] -= 1
            resp = await self._active_probe(ip, port, payload)
            if resp and matcher(resp):
                return self._db_findings(name, ip, port, f"{name} handshake confirmed")
        if budget[0] > 0:
            budget[0] -= 1
            resp = await self._active_probe(ip, port, _REDIS_PING)
            state = self._redis_state(resp)
            if state:
                return self._redis_findings(state, ip, port)
        return []

    async def _read_passive(self, ip: str, port: int, timeout: float = 3.0) -> bytes:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        except Exception:  # noqa: BLE001
            return b""
        try:
            return await asyncio.wait_for(reader.read(256), timeout=timeout)
        except Exception:  # noqa: BLE001
            return b""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _active_probe(self, ip: str, port: int, payload: bytes, timeout: float = 4.0) -> bytes:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        except Exception:  # noqa: BLE001
            return b""
        try:
            writer.write(payload)
            await writer.drain()
            return await asyncio.wait_for(reader.read(256), timeout=timeout)
        except Exception:  # noqa: BLE001
            return b""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _redis_state(resp: bytes) -> str | None:
        if not resp:
            return None
        if resp.startswith(b"+PONG") or b"PONG" in resp:
            return "unauth"
        if b"NOAUTH" in resp:
            return "auth"
        return None

    # ── finding builders ────────────────────────────────────────────────────
    def _banner_findings(self, kind: str, ip: str, port: int, banner: str) -> list[FindingData]:
        meta = {
            "vnc": (Severity.low, "VNC Service on Non-Standard Port",
                    "A VNC remote-desktop service is exposed here. VNC often has weak or legacy "
                    "authentication and should not be internet-facing.",
                    "Restrict VNC to trusted networks/VPN and require strong authentication."),
            "smtp": (Severity.info, "SMTP Service on Non-Standard Port",
                     "An SMTP mail service is exposed on a non-standard port.",
                     "Confirm this mail service is intended and not an open relay; restrict access."),
            "ftp": (Severity.low, "FTP Service on Non-Standard Port",
                    "An FTP service is exposed here. FTP transmits credentials and data in cleartext.",
                    "Replace FTP with SFTP/FTPS and restrict access."),
        }
        sev, title, desc, remediation = meta[kind]
        return [FindingData(
            plugin_id=self.id, severity=sev, title=f"{title} ({port})", description=desc,
            evidence=f"{ip}:{port} banner: {banner[:200]}" if banner else f"{ip}:{port}",
            remediation=remediation,
            references=["https://cwe.mitre.org/data/definitions/1327.html"],
            port_number=port, protocol="tcp",
        )]

    def _db_findings(self, kind: str, ip: str, port: int, evidence: str) -> list[FindingData]:
        label = {"mysql": "MySQL", "postgresql": "PostgreSQL", "mongodb": "MongoDB", "rdp": "RDP"}[kind]
        is_db = kind in ("mysql", "postgresql", "mongodb")
        desc = (
            f"A {label} database is exposed on a non-standard port. Databases should never be "
            "internet-facing; verify authentication and network restrictions."
            if is_db else
            f"An RDP (Remote Desktop) service is exposed on a non-standard port {port}. "
            "Internet-facing RDP is a top ransomware entry point."
        )
        remediation = (
            f"Bind {label} to localhost/trusted networks, require strong auth, and firewall the port."
            if is_db else
            "Restrict RDP to VPN/trusted networks, enforce NLA, and use strong credentials + MFA."
        )
        return [FindingData(
            plugin_id=self.id, severity=Severity.medium,
            title=f"{label} Service on Non-Standard Port ({port})",
            description=desc, evidence=f"{ip}:{port} — {evidence}", remediation=remediation,
            references=["https://cwe.mitre.org/data/definitions/1327.html"],
            port_number=port, protocol="tcp",
        )]

    def _redis_findings(self, state: str, ip: str, port: int) -> list[FindingData]:
        if state == "unauth":
            return [FindingData(
                plugin_id=self.id, severity=Severity.high,
                title=f"Unauthenticated Redis on Non-Standard Port ({port})",
                description=(
                    "A Redis server on a non-standard port accepts commands without authentication. "
                    "An attacker can read/write all data and often achieve remote code execution "
                    "(e.g. via CONFIG SET + module load or writing an SSH key/cron job)."
                ),
                evidence=f"{ip}:{port} replied +PONG to an unauthenticated PING",
                remediation="Require a password (requirepass) / ACLs, bind to localhost, and firewall the port.",
                references=["https://redis.io/docs/management/security/"],
                port_number=port, protocol="tcp",
            )]
        return [FindingData(
            plugin_id=self.id, severity=Severity.low,
            title=f"Redis Service on Non-Standard Port ({port})",
            description="A password-protected Redis server is exposed on a non-standard port.",
            evidence=f"{ip}:{port} replied -NOAUTH to PING",
            remediation="Confirm the exposure is intended; restrict Redis to trusted networks.",
            port_number=port, protocol="tcp",
        )]
