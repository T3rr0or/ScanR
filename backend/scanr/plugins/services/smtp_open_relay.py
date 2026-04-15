from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class SmtpOpenRelayPlugin(PluginBase):
    id = "services.smtp_open_relay"
    name = "SMTP Open Relay"
    description = "Test SMTP server for open relay (unauthenticated mail forwarding)"
    category = PluginCategory.services
    severity = Severity.high
    ports = [25, 587, 2525]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in self.ports or port.state != "open":
                continue
            is_relay = await self._test_relay(host.ip, port.number)
            if is_relay:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="SMTP Open Relay Detected",
                    description=(
                        "The SMTP server accepts mail for arbitrary external domains without authentication. "
                        "Open relays are used by spammers and can result in blacklisting."
                    ),
                    evidence=f"RCPT TO: external@example.com accepted without authentication on {host.ip}:{port.number}",
                    remediation="Configure the SMTP server to only relay mail for authenticated users and authorized local domains.",
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    async def _test_relay(self, ip: str, port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5
            )
            await asyncio.wait_for(reader.read(1024), timeout=3)  # banner
            writer.write(b"HELO scanr.example.com\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.write(b"MAIL FROM:<test@scanr.example.com>\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=3)
            if not resp.startswith(b"250"):
                writer.close()
                return False
            writer.write(b"RCPT TO:<test@external-domain-xyz.com>\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            return resp.startswith(b"250")
        except Exception:
            return False
