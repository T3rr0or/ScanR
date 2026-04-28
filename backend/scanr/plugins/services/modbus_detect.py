from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)


class ModbusDetectPlugin(PluginBase):
    id = "services.modbus_detect"
    name = "Modbus/TCP Industrial Protocol Detection"
    description = "Detect exposed Modbus/TCP industrial control system protocol (detection only — read-only FC01/FC03/FC17 probes)"
    category = PluginCategory.services
    severity = Severity.critical
    ports = [502]
    destructive = False  # FC01/FC03/FC17 are read-only; no write functions used

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings = []
        for port in host.ports:
            if port.number != 502 or port.state != "open":
                continue
            result = await asyncio.get_running_loop().run_in_executor(
                None, self._probe_modbus, host.ip, port.number
            )
            if result:
                findings.append(self._make_finding(host.ip, port.number, result))
        return findings

    def _probe_modbus(self, ip: str, port: int) -> dict | None:
        import socket
        import struct

        results = {"function_codes": [], "slave_id": None, "data": []}

        def send_recv(sock, payload):
            sock.sendall(payload)
            return sock.recv(512)

        try:
            sock = socket.create_connection((ip, port), timeout=5)

            # FC 01 - Read Coils (unit 1, addr 0, count 8)
            fc01_pdu = bytes([0x01, 0x01, 0x00, 0x00, 0x00, 0x08])
            fc01_req = struct.pack(">HHH", 0x0001, 0x0000, len(fc01_pdu)) + fc01_pdu
            resp = send_recv(sock, fc01_req)
            if len(resp) >= 7:
                proto_id = struct.unpack_from(">H", resp, 2)[0]
                func_code = resp[7] if len(resp) > 7 else 0
                if proto_id == 0x0000 and func_code in (0x01, 0x81):
                    results["function_codes"].append("FC01-ReadCoils")

            # FC 03 - Read Holding Registers (unit 1, addr 0, count 10)
            fc03_pdu = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
            fc03_req = struct.pack(">HHH", 0x0002, 0x0000, len(fc03_pdu)) + fc03_pdu
            resp = send_recv(sock, fc03_req)
            if len(resp) >= 7:
                func_code = resp[7] if len(resp) > 7 else 0
                if func_code in (0x03, 0x83):
                    results["function_codes"].append("FC03-ReadHoldingRegisters")
                    if func_code == 0x03 and len(resp) > 9:
                        byte_count = resp[8]
                        reg_data = resp[9:9 + byte_count]
                        if reg_data:
                            regs = [
                                struct.unpack_from(">H", reg_data, i)[0]
                                for i in range(0, min(len(reg_data) - 1, 10), 2)
                            ]
                            results["data"] = regs[:5]

            # FC 17 - Report Slave ID (device identification)
            fc17_pdu = bytes([0x01, 0x11])
            fc17_req = struct.pack(">HHH", 0x0003, 0x0000, len(fc17_pdu)) + fc17_pdu
            resp = send_recv(sock, fc17_req)
            if len(resp) >= 8 and resp[7] == 0x11:
                if len(resp) > 9:
                    slave_data = resp[9:]
                    results["slave_id"] = slave_data.decode(errors="ignore").strip()[:100]
                    results["function_codes"].append("FC17-ReportSlaveID")

            sock.close()

            if results["function_codes"]:
                return results
            return None
        except Exception:
            return None

    def _make_finding(self, ip: str, port: int, results: dict) -> FindingData:
        fc_list = ", ".join(results["function_codes"])
        slave_id = results["slave_id"] or "N/A"
        data = results["data"] or []
        evidence_lines = [
            f"Function codes responded: {fc_list}",
            f"Device ID: {slave_id}",
            f"Sample registers: {data}",
        ]
        return FindingData(
            plugin_id=self.id,
            severity=Severity.critical,
            title="Modbus Industrial Protocol Exposed",
            description=(
                "Unauthenticated Modbus access to industrial control systems. "
                "No authentication or encryption. "
                "Can read sensor values, write coils/registers, potentially control physical processes."
            ),
            evidence="\n".join(evidence_lines),
            remediation=(
                "Modbus was designed for isolated industrial networks. Place behind industrial firewall. "
                "Use encrypted tunnels (VPN) for any remote access. "
                "Implement Modbus firewall/DPI rules."
            ),
            references=[
                "https://www.cisa.gov/sites/default/files/recommended_practices/final-RP_ICS_cybersecurity_incident_response_100609.pdf",
            ],
            port_number=port,
            protocol="tcp",
        )
