"""NTP monlist amplification check plugin.

CVE-2013-5211: NTP servers with monlist enabled respond to a 48-byte request
with up to 6000 bytes per packet (amplification factor ~125x), enabling DDoS.

This is a safe detection-only probe — we send the monlist request and check
whether we receive a larger-than-expected response.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

# NTP mode 7 private request: REQ_MON_GETLIST_1 (monlist)
_MONLIST_REQ = bytes([
    0x17, 0x00, 0x03, 0x2a,  # LI=0, VN=2, Mode=7, seq=0, impl=3, req=42
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
])


class NtpMonlistPlugin(PluginBase):
    id = "services.ntp_monlist"
    name = "NTP Monlist Amplification"
    description = "Detect NTP servers with monlist enabled (CVE-2013-5211)"
    category = PluginCategory.services
    severity = Severity.medium
    cve_ids = ["CVE-2013-5211"]
    ports = [123]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        if not any(p.number == 123 and p.state == "open" for p in host.ports):
            return []

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self._probe_monlist, host.ip)
        if not result:
            return []

        response_size = result
        amplification = round(response_size / len(_MONLIST_REQ), 1)
        return [FindingData(
            plugin_id=self.id,
            severity=Severity.medium,
            title="NTP Monlist Amplification Enabled (CVE-2013-5211)",
            description=(
                "The NTP server responds to monlist requests, allowing amplification attacks. "
                f"A {len(_MONLIST_REQ)}-byte request returned {response_size} bytes "
                f"(~{amplification}x amplification). Attackers can use this server "
                "as a DDoS amplifier by spoofing UDP source addresses."
            ),
            evidence=f"NTP monlist response received from {host.ip}:123 — {response_size} bytes",
            remediation=(
                "Disable monlist in ntp.conf with 'restrict default noquery'. "
                "Upgrade ntpd to 4.2.7p26 or later. Consider switching to chrony or systemd-timesyncd."
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2013-5211"],
            cve_ids=self.cve_ids,
            port_number=123,
            protocol="udp",
        )]

    def _probe_monlist(self, ip: str) -> int | None:
        """Returns total bytes received if monlist responds, else None."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(_MONLIST_REQ, (ip, 123))
            total = 0
            # Monlist can send multiple UDP packets
            for _ in range(10):
                try:
                    data, _ = sock.recvfrom(4096)
                    # Check NTP mode 7 response (byte 0 & 0x07 == 7)
                    if data and (data[0] & 0x07) == 7:
                        total += len(data)
                    else:
                        break
                except socket.timeout:
                    break
            sock.close()
            return total if total > 0 else None
        except Exception:
            return None
