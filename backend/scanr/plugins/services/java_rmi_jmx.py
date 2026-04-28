"""Java RMI / JMX unauthenticated access detection.

Java RMI (Remote Method Invocation) and JMX (Java Management Extensions)
registries exposed on the network allow remote code execution when not
protected by authentication. Attackers can use tools like mjet or ysoserial
to exploit unauthenticated JMX endpoints.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

_RMI_PORTS = (1099, 1098, 2099, 4444, 44444)


class JavaRmiJmxPlugin(PluginBase):
    id = "services.java_rmi_jmx"
    name = "Java RMI/JMX Registry Exposed"
    description = "Detect unauthenticated Java RMI/JMX registries that allow remote code execution"
    category = PluginCategory.services
    severity = Severity.high
    ports = list(_RMI_PORTS)

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in _RMI_PORTS or port.state != "open":
                continue
            result = await asyncio.get_running_loop().run_in_executor(
                None, self._probe_rmi, host.ip, port.number
            )
            if result:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.high,
                    title="Java RMI/JMX Registry Accessible",
                    description=(
                        "A Java RMI or JMX registry is accessible on this port without "
                        "authentication. Attackers can list registered objects and potentially "
                        "invoke methods or exploit deserialization vulnerabilities to achieve "
                        "remote code execution using tools like ysoserial."
                    ),
                    evidence=f"RMI handshake accepted on {host.ip}:{port.number} — {result}",
                    remediation=(
                        "Restrict RMI/JMX access with a firewall to trusted hosts only. "
                        "Enable JMX authentication and SSL by setting "
                        "-Dcom.sun.jndi.rmi.object.trustURLCodebase=false and configuring "
                        "a password file. Do not expose RMI registries to untrusted networks."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1203/",
                        "https://owasp.org/www-community/vulnerabilities/Unsafe_use_of_Reflection",
                    ],
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    def _probe_rmi(self, ip: str, port: int) -> str | None:
        """Send RMI handshake and check for valid RMI response. Returns description or None."""
        # Java RMI protocol: client sends "JRMI" magic + version, server echoes back
        rmi_header = b"JRMI\x00\x02K"  # magic + version 2 + StreamProtocol
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            sock.sendall(rmi_header)
            resp = sock.recv(64)
            sock.close()
            if resp and resp[:4] == b"JRMI":
                return f"RMI protocol version {resp[4]:02x}{resp[5]:02x}"
            # Also check for serialized Java object header (0xACED 0x0005)
            if len(resp) >= 2 and resp[0] == 0xAC and resp[1] == 0xED:
                return "Java serialized stream"
            if resp:
                return f"response: {resp[:8].hex()}"
        except Exception:
            pass
        return None
