"""Android Debug Bridge (ADB) unauthenticated access check.

ADB exposed on port 5555 (or other ports) allows unauthenticated remote shell
access to Android devices and some IoT devices. An attacker can install
malware, extract data, or use the device as a pivot.
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

_ADB_PORTS = (5555, 5554, 5556, 5037)
_ADB_MAGIC = 0x41444242  # 'ADBB'


class AdbUnauthPlugin(PluginBase):
    id = "services.adb_unauth"
    name = "ADB Unauthenticated Access"
    description = "Detect Android Debug Bridge (ADB) exposed without authentication"
    category = PluginCategory.services
    severity = Severity.critical
    ports = list(_ADB_PORTS)

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number not in _ADB_PORTS or port.state != "open":
                continue
            device_info = await asyncio.get_running_loop().run_in_executor(
                None, self._probe_adb, host.ip, port.number
            )
            if device_info is not None:
                findings.append(FindingData(
                    plugin_id=self.id,
                    severity=Severity.critical,
                    title="ADB Accessible Without Authentication",
                    description=(
                        "The Android Debug Bridge (ADB) service is accepting connections "
                        "on this port without requiring authentication. An attacker can "
                        "gain a remote shell with the device's privilege level, install "
                        "malicious applications, read sensitive files, or use the device "
                        "as a network pivot."
                    ),
                    evidence=f"ADB connection accepted on {host.ip}:{port.number}"
                              + (f" — {device_info}" if device_info else ""),
                    remediation=(
                        "Disable ADB over network if not required (default on production "
                        "Android devices). If remote ADB is needed, enable ADB authentication "
                        "(Android 4.2.2+) and restrict access via firewall to trusted IPs only. "
                        "Never expose ADB on internet-facing interfaces."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1219/",
                        "https://developer.android.com/studio/command-line/adb",
                    ],
                    port_number=port.number,
                    protocol="tcp",
                ))
        return findings

    def _probe_adb(self, ip: str, port: int) -> str | None:
        """Send ADB CNXN packet and check for device response. Returns device serial or '' on success."""
        # ADB message structure: command(4) arg0(4) arg1(4) data_length(4) crc32(4) magic(4)
        # CNXN command = 0x4e584e43 ('CNXN')
        host_id = b"host::features=shell_v2,cmd\x00"
        msg = struct.pack(
            "<IIIIII",
            0x4e584e43,     # CNXN command
            0x01000000,     # version
            1024 * 1024,    # max data
            len(host_id),   # data length
            self._crc32(host_id),
            0x4e584e43 ^ 0xFFFFFFFF,  # magic
        ) + host_id

        try:
            sock = socket.create_connection((ip, port), timeout=5)
            sock.sendall(msg)
            resp = sock.recv(256)
            sock.close()
            if len(resp) >= 4:
                cmd = struct.unpack_from("<I", resp)[0]
                if cmd == 0x4e584e43:  # CNXN response
                    # Extract device info from data portion
                    if len(resp) >= 24:
                        data_len = struct.unpack_from("<I", resp, 12)[0]
                        data = resp[24:24 + data_len]
                        return data.decode("utf-8", errors="replace").strip("\x00")
                    return ""
                if cmd == 0x48545541:  # AUTH — authentication required
                    return None
            return None
        except Exception:
            return None

    def _crc32(self, data: bytes) -> int:
        import binascii
        return binascii.crc32(data) & 0xFFFFFFFF
