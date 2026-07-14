from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.ssl_tls._ports import is_tls_port

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)
SSL_PORTS = [443, 8443, 993, 995, 465, 636]


class ProtocolCheckPlugin(PluginBase):
    id = "ssl_tls.protocol_check"
    name = "Deprecated TLS/SSL Protocol Detection"
    description = "Detect servers accepting SSLv2, SSLv3, TLS 1.0, or TLS 1.1"
    category = PluginCategory.ssl_tls
    severity = Severity.high
    ports = SSL_PORTS

    DEPRECATED = [
        (ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None, "TLS 1.0", Severity.high),
    ]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if not is_tls_port(port):
                continue
            for proto_const, proto_name, sev in self.DEPRECATED:
                if proto_const is None:
                    continue
                supported = await self._test_protocol(host.ip, port.number, proto_const)
                if supported:
                    findings.append(FindingData(
                        plugin_id=self.id,
                        severity=sev,
                        title=f"Deprecated Protocol Supported: {proto_name}",
                        description=f"Server on port {port.number} accepts connections using {proto_name}, which is considered insecure.",
                        evidence=f"{proto_name} handshake succeeded",
                        remediation=f"Disable {proto_name} and configure the server to use TLS 1.2 or TLS 1.3 only.",
                        references=["https://datatracker.ietf.org/doc/rfc8996/"],
                        port_number=port.number,
                        protocol="tcp",
                    ))
        return findings

    async def _test_protocol(self, ip: str, port: int, proto_const) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._test_sync, ip, port, proto_const)

    def _test_sync(self, ip: str, port: int, proto_const) -> bool:
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=5) as sock:
                with ctx.wrap_socket(sock):
                    return True
        except Exception:
            return False
