"""RDP metadata extraction.

Extracts hostname, domain, and FQDN from the RDP server's negotiation
response. This information is useful for understanding the network topology
and identifying Active Directory membership.
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


class RdpInfoPlugin(PluginBase):
    id = "services.rdp_info"
    name = "RDP Service Information"
    description = "Extract hostname, domain, and FQDN from RDP negotiation response"
    category = PluginCategory.services
    severity = Severity.info
    ports = [3389]

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        for port in host.ports:
            if port.number != 3389 or port.state != "open":
                continue
            info = await asyncio.get_running_loop().run_in_executor(
                None, self._extract_rdp_info, host.ip, 3389
            )
            if not info:
                return []
            details = []
            if info.get("hostname"):
                details.append(f"Hostname: {info['hostname']}")
            if info.get("domain"):
                details.append(f"Domain: {info['domain']}")
            if info.get("fqdn"):
                details.append(f"FQDN: {info['fqdn']}")
            if not details:
                return []
            return [FindingData(
                plugin_id=self.id,
                severity=Severity.info,
                title="RDP Service Exposes System Metadata",
                description=(
                    "The RDP service discloses system information during the negotiation "
                    "phase without requiring authentication. This information aids attackers "
                    "in mapping the internal network and identifying AD-joined machines."
                ),
                evidence="\n".join(details),
                remediation=(
                    "If RDP is required, restrict access via firewall rules to authorized "
                    "source IPs only. Consider using Network Level Authentication (NLA) to "
                    "reduce pre-authentication exposure."
                ),
                references=["https://attack.mitre.org/techniques/T1046/"],
                port_number=3389,
                protocol="tcp",
            )]
        return []

    def _extract_rdp_info(self, ip: str, port: int) -> dict | None:
        # TPKT + X.224 Connection Request with RDP negotiation
        rdp_neg_req = (
            b"\x03\x00\x00\x13"   # TPKT header (length 19)
            b"\x0e\xe0\x00\x00"   # X.224 CR TPDU
            b"\x00\x00\x00\x00\x00"
            b"\x01\x00\x08\x00"   # RDP_NEG_REQ, flags=0, length=8
            b"\x03\x00\x00\x00"   # requestedProtocols: PROTOCOL_HYBRID|SSL
        )
        try:
            sock = socket.create_connection((ip, port), timeout=8)
            sock.sendall(rdp_neg_req)
            sock.recv(1024)
            sock.close()
        except Exception:
            return None

        # After TPKT+X224 the server may send NegoData with server certificate
        # containing name info. Try to parse via rdp library if available.
        return self._parse_via_impacket(ip, port) or {}

    def _parse_via_impacket(self, ip: str, port: int) -> dict | None:
        """Use impacket's RDP scanner to extract domain/hostname metadata."""
        # Fallback: connect and scrape the certificate SAN/CN
        try:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Raw TLS connection after RDP negotiation
            raw = socket.create_connection((ip, port), timeout=8)
            # Send TPKT negotiation to upgrade to TLS
            neg = (
                b"\x03\x00\x00\x13"
                b"\x0e\xe0\x00\x00\x00\x00\x00\x00\x00"
                b"\x01\x00\x08\x00\x01\x00\x00\x00"
            )
            raw.sendall(neg)
            raw.recv(19)  # consume server response

            tls_sock = ctx.wrap_socket(raw, server_hostname=ip)
            cert = tls_sock.getpeercert(binary_form=False)
            tls_sock.close()

            info: dict = {}
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                cn = subject.get("commonName", "")
                if cn:
                    info["fqdn"] = cn
                    parts = cn.split(".", 1)
                    if len(parts) == 2:
                        info["hostname"] = parts[0]
                        info["domain"] = parts[1]
                for san_type, san_value in cert.get("subjectAltName", []):
                    if san_type == "DNS" and san_value not in info.values():
                        info.setdefault("fqdn", san_value)
            return info if info else None
        except Exception:
            return None
