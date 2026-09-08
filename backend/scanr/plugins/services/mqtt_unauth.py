"""MQTT anonymous access detection.

MQTT brokers ship with ``allow_anonymous true`` in most default configs
(Mosquitto <2.0, most vendor IoT gateways). An anonymous client is not merely a
reader: MQTT has no per-topic ACL unless one is configured, so the same session
that reads telemetry can PUBLISH to command topics — door controllers, PLC
setpoints, alarm mutes. That is why this is high and not informational.

The probe is read-only: a CONNECT with no credentials, and — only if the broker
accepts it — a SUBSCRIBE to ``$SYS/#``, the broker's own read-only statistics
tree. We never PUBLISH.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import struct
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

MQTT_PORTS = [1883, 8883]
# 8883 is the IANA-registered MQTT-over-TLS port; 1883 is plaintext.
TLS_PORTS = {8883}

# CONNACK return codes for MQTT 3.1.1 (protocol level 4). Anything outside this
# set means we are not talking to an MQTT broker, so we refuse to report.
_CONNACK_CODES = {
    0x00: "Connection Accepted",
    0x01: "Unacceptable Protocol Version",
    0x02: "Identifier Rejected",
    0x03: "Server Unavailable",
    0x04: "Bad User Name or Password",
    0x05: "Not Authorized",
    # MQTT 5.0 reason codes a v5 broker may return to a v3.1.1 CONNECT.
    0x84: "Unsupported Protocol Version",
    0x86: "Bad User Name or Password",
    0x87: "Not Authorized",
}

_SYS_TOPIC = b"$SYS/#"


def _encode_remaining_length(length: int) -> bytes:
    """MQTT's variable-length integer encoding (7 bits per byte, MSB = continue)."""
    out = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length:
            digit |= 0x80
        out.append(digit)
        if not length:
            break
    return bytes(out)


def _build_connect(client_id: bytes = b"scanr-probe") -> bytes:
    """CONNECT with clean session, no username, no password, no will."""
    variable_header = (
        struct.pack(">H", 4) + b"MQTT"   # protocol name
        + b"\x04"                        # protocol level 4 = MQTT 3.1.1
        + b"\x02"                        # connect flags: clean session only
        + struct.pack(">H", 60)          # keep alive
    )
    payload = struct.pack(">H", len(client_id)) + client_id
    body = variable_header + payload
    return b"\x10" + _encode_remaining_length(len(body)) + body


def _build_subscribe(topic: bytes = _SYS_TOPIC, packet_id: int = 1) -> bytes:
    """SUBSCRIBE at QoS 0. Fixed header 0x82 (type 8, reserved bits 0010)."""
    body = struct.pack(">H", packet_id) + struct.pack(">H", len(topic)) + topic + b"\x00"
    return b"\x82" + _encode_remaining_length(len(body)) + body


def _parse_connack(data: bytes | None) -> int | None:
    """Return the CONNACK return code, or None if this is not a CONNACK."""
    if not data or len(data) < 4:
        return None
    if data[0] != 0x20:  # packet type 2 (CONNACK), flags 0
        return None
    code = data[3]
    if code not in _CONNACK_CODES:
        return None
    return code


def _suback_granted(data: bytes | None) -> bool:
    """True when the broker granted the $SYS subscription (SUBACK code != 0x80)."""
    if not data or len(data) < 5:
        return False
    if data[0] != 0x90:  # packet type 9 (SUBACK)
        return False
    return data[4] in (0x00, 0x01, 0x02)


class MqttUnauthPlugin(PluginBase):
    id = "services.mqtt_unauth"
    name = "MQTT Broker Anonymous Access"
    description = "Detect MQTT brokers that accept CONNECT without credentials"
    category = PluginCategory.services
    severity = Severity.high
    ports = MQTT_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in MQTT_PORTS or port.state != "open":
                continue
            try:
                raw = await self._probe(host.ip, port.number)
            except Exception:
                logger.debug("mqtt_unauth: probe failed for %s:%d", host.ip, port.number, exc_info=True)
                continue
            if raw is None:
                continue
            connack, suback = raw
            finding = self._analyze(host.ip, port.number, connack, suback)
            if finding:
                findings.append(finding)
        return findings

    async def _probe(self, ip: str, port: int) -> tuple[bytes, bytes | None] | None:
        """Send CONNECT (and $SYS SUBSCRIBE on success). Returns the raw replies."""
        ssl_ctx = None
        if port in TLS_PORTS:
            # Brokers on 8883 routinely use private CAs; we are fingerprinting the
            # auth policy, not validating the chain, so verification is off here.
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx), timeout=6.0
            )
            writer.write(_build_connect())
            await writer.drain()
            connack = await asyncio.wait_for(reader.read(64), timeout=5.0)
            if not connack:
                return None

            suback: bytes | None = None
            if _parse_connack(connack) == 0x00:
                writer.write(_build_subscribe())
                await writer.drain()
                suback = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            return connack, suback
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def _analyze(
        self, ip: str, port: int, connack: bytes | None, suback: bytes | None
    ) -> FindingData | None:
        code = _parse_connack(connack)
        if code is None:
            # Not an MQTT broker (or a truncated/garbage reply) — never report.
            return None
        if code != 0x00:
            # The broker rejected us. Even "Identifier Rejected" is a refusal,
            # so anonymous access is not proven and we stay quiet.
            return None

        tls = port in TLS_PORTS
        sys_readable = _suback_granted(suback)
        evidence = (
            f"CONNECT (no username, no password) -> CONNACK 0x00 "
            f"({_CONNACK_CODES[0x00]}) on {ip}:{port}"
            + (" over TLS" if tls else " in cleartext")
        )
        if sys_readable:
            evidence += f"; SUBSCRIBE {_SYS_TOPIC.decode()} -> SUBACK granted (broker statistics readable)"

        description = (
            f"The MQTT broker on port {port} accepted a CONNECT packet with no username "
            "and no password. Unless topic-level ACLs are configured, an anonymous client "
            "can subscribe to every topic on the broker — reading sensor telemetry, "
            "location data, and device credentials passed as payloads — and can also "
            "PUBLISH to command topics, letting an attacker actuate whatever the "
            "connected devices control."
        )
        if sys_readable:
            description += (
                " The broker additionally served the $SYS tree, exposing version, uptime, "
                "client counts and message throughput to the same anonymous session."
            )
        if not tls:
            description += (
                " The connection is unencrypted, so any credentials used by legitimate "
                "clients on this port are also recoverable from the network."
            )

        return FindingData(
            plugin_id=self.id,
            severity=Severity.high,
            title="MQTT Broker Allows Anonymous Access",
            description=description,
            evidence=evidence,
            remediation=(
                "Set 'allow_anonymous false' (Mosquitto) or the equivalent for your broker "
                "and require per-client credentials or mutual TLS client certificates. "
                "Define per-topic ACLs so an authenticated client can only reach its own "
                "topics — authentication alone still leaves every topic readable. "
                "Restrict the $SYS tree to administrators. "
                "Terminate MQTT on 8883 with TLS and firewall 1883 off the perimeter."
            ),
            references=[
                "https://mosquitto.org/man/mosquitto-conf-5.html",
                "https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html",
                "https://cwe.mitre.org/data/definitions/306.html",
            ],
            port_number=port,
            protocol="tcp",
        )
