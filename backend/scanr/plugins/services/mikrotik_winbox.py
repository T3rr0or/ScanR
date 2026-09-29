"""MikroTik RouterOS Winbox exposure and CVE-2018-14847 detection.

Winbox is RouterOS's management protocol on TCP 8291. CVE-2018-14847 is an
unauthenticated directory traversal in that service (RouterOS before 6.42.1)
that reads the user database and has been mass-exploited to seize routers.

This check reports two things:

  * The Winbox management port being reachable at all — a hardening finding in
    its own right; MikroTik's guidance is to keep it off untrusted networks.
  * When a RouterOS version can be read from the service's own, non-traversal
    handshake, whether that version is in the CVE-2018-14847 affected range.

It deliberately does **not** send the ``//./..`` traversal that the public
exploit uses to read ``user.dat`` — that would be reading credentials off the
device. It only issues the ordinary index request the Winbox client itself
sends, and parses the version the server returns. Version boundaries are from
the CVE record and MikroTik's advisory.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

WINBOX_PORT = 8291
_TIMEOUT = 5.0

# Safe Winbox index request used by Nmap's official mikrotik-routeros-version
# NSE script. The index response includes plugin DLL names and their RouterOS
# versions. This is not the CVE-2018-14847 file traversal request.
_WINBOX_INDEX_REQUEST = (
    b"\x13\x02index\x00\x00\x00\x00\x00\x00\x00\xff\xed\x00\x00\x00\x00\x00"
)

_VERSION_RE = re.compile(rb"[A-Za-z0-9_]+\.dll\s+([0-9]+(?:\.[0-9]+)+)")

REFERENCES = [
    "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
    "https://blog.mikrotik.com/security/winbox-vulnerability.html",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
]


def parse_ros_version(text: str) -> tuple[int, ...] | None:
    """Parse a RouterOS version like '6.42.12' or '6.40' into a tuple."""
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        return None
    parts = [int(m.group(1)), int(m.group(2))]
    if m.group(3) is not None:
        parts.append(int(m.group(3)))
    return tuple(parts)


def is_vulnerable_14847(version: tuple[int, ...]) -> bool:
    """CVE-2018-14847 affects RouterOS before 6.42.1.

    MikroTik backported the fix to the 6.40.x long-term branch at 6.40.8, so
    6.40.8 <= v < 6.41 is patched even though it is below 6.42.1. The 6.41.x
    train is not fixed until 6.42.1. Guard a sensible floor (>= 6.0) so a
    mis-parsed token cannot flag ancient nonsense.
    """
    if version < (6, 0):
        return False
    if (6, 40, 8) <= version < (6, 41):
        return False
    return version < (6, 42, 1)


def _extract_ros_version(data: bytes) -> str | None:
    """Extract a RouterOS version from an index response's ``name.dll version`` rows."""
    best: tuple[int, ...] | None = None
    best_str: str | None = None
    for m in _VERSION_RE.finditer(data):
        token = m.group(1).decode("ascii", errors="ignore")
        version = parse_ros_version(token)
        if version is None or version[0] not in (6, 7):
            continue
        if best is None or version > best:
            best = version
            best_str = token
    return best_str


async def _winbox_probe(ip: str, port: int) -> bytes | None:
    """Connect, send the non-traversal index request, return the reply bytes.

    Best-effort and fully defensive: any protocol deviation yields None, and the
    caller still reports the port exposure.
    """
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=_TIMEOUT)
        writer.write(_WINBOX_INDEX_REQUEST)
        await writer.drain()
        # The NSE protocol reader consumes a 20-byte response header, whose
        # signed big-endian body length is at bytes 14-15, then the full body.
        header = await asyncio.wait_for(reader.readexactly(20), timeout=_TIMEOUT)
        body_len = int.from_bytes(header[14:16], "big", signed=True)
        if body_len < 0:
            return header
        if body_len > 65536:
            return None
        body = await asyncio.wait_for(reader.readexactly(body_len), timeout=_TIMEOUT)
        return header + body
    except Exception:
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


class MikrotikWinboxPlugin(PluginBase):
    id = "services.mikrotik_winbox"
    name = "MikroTik Winbox Exposure (CVE-2018-14847)"
    description = "Detect exposed MikroTik Winbox service and RouterOS versions vulnerable to CVE-2018-14847"
    category = PluginCategory.services
    severity = Severity.high
    cve_ids = ["CVE-2018-14847"]
    ports = [WINBOX_PORT]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.state != "open" or port.number != WINBOX_PORT:
                continue
            finding = await self._probe(host.ip, port.number)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, ip: str, port: int) -> FindingData | None:
        data = await _winbox_probe(ip, port)
        version_str = _extract_ros_version(data) if data else None
        version = parse_ros_version(version_str) if version_str else None

        if version is not None and is_vulnerable_14847(version):
            return FindingData(
                plugin_id=self.id,
                severity=Severity.high,
                title=f"MikroTik RouterOS {version_str} vulnerable to CVE-2018-14847 (Winbox)",
                description=(
                    f"The Winbox service on port {port} reports RouterOS {version_str}, which predates the "
                    "6.42.1 fix for CVE-2018-14847. This is an unauthenticated directory traversal in Winbox "
                    "that reads the router's user database; it has been used at scale to extract administrator "
                    "credentials and take over MikroTik routers."
                ),
                evidence=f"{ip}:{port} Winbox reported RouterOS version {version_str}",
                remediation=(
                    "Upgrade RouterOS to 6.42.1 or later (or 6.40.8+ on the long-term branch), then rotate all "
                    "router credentials — assume they were readable. Restrict Winbox (8291) to trusted "
                    "management networks and disable unused management services."
                ),
                references=REFERENCES,
                cve_ids=["CVE-2018-14847"],
                port_number=port,
                protocol="tcp",
            )

        if version is not None:
            return FindingData(
                plugin_id=self.id,
                severity=Severity.low,
                title=f"MikroTik Winbox exposed (RouterOS {version_str})",
                description=(
                    f"The MikroTik Winbox management service is reachable on port {port} (RouterOS {version_str}). "
                    "The version is patched for CVE-2018-14847, but exposing Winbox to untrusted networks widens "
                    "the management attack surface."
                ),
                evidence=f"{ip}:{port} Winbox reported RouterOS version {version_str}",
                remediation=(
                    "Restrict Winbox (8291) to trusted management networks or a VPN, and keep RouterOS current."
                ),
                references=REFERENCES,
                port_number=port,
                protocol="tcp",
            )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title="MikroTik Winbox management port exposed",
            description=(
                f"TCP port {port} (MikroTik Winbox) is reachable. The RouterOS version could not be read, so "
                "CVE-2018-14847 exploitability is unconfirmed, but an exposed Winbox interface should not be "
                "reachable from untrusted networks: affected RouterOS builds are vulnerable to an "
                "unauthenticated credential-disclosure traversal over exactly this port."
            ),
            evidence=f"{ip}:{port}/tcp open (MikroTik Winbox)",
            remediation=(
                "Confirm RouterOS has the 6.42.1 fix (or the 6.40.8 long-term backport), restrict Winbox (8291) to trusted management "
                "networks or a VPN, and disable it on the WAN interface."
            ),
            references=REFERENCES,
            cve_ids=[],
            port_number=port,
            protocol="tcp",
        )
