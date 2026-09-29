"""Unauthenticated iSCSI target exposure (TCP/3260).

iSCSI presents raw block devices over the network. A client that can complete a
discovery session gets the list of targets; a client that can log into a target
gets the disk, at the block level, as though it were locally attached. There is
no filesystem permission model in the way — mount the volume elsewhere and every
file on it is readable and writable.

Authentication is optional in the protocol and off by default in several
implementations. CHAP has to be configured deliberately, and initiator-IQN
allowlisting is often used instead, which is not authentication at all: an IQN is
a string the client chooses.

What this exposes is usually the most valuable data on the network: iSCSI
typically backs VM datastores, database volumes and backup repositories. An
attacker with block access to a VMware datastore has every virtual machine's
disk, and an attacker with block access to a backup volume has both the backups
and the ability to destroy them.

The check performs a discovery-session login and, if that succeeds without
credentials, a ``SendTargets`` text request — the same two steps an initiator
takes before mounting anything. It never logs into a target, so no volume is
attached and nothing on a disk is read or written.
"""
from __future__ import annotations

import asyncio
import logging
import re
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

ISCSI_PORTS = [3260]

_TIMEOUT = 6.0
_BHS_LENGTH = 48
_READ_LIMIT = 65536

_OPCODE_LOGIN_REQUEST = 0x03
_OPCODE_LOGIN_RESPONSE = 0x23
_OPCODE_TEXT_REQUEST = 0x04
_OPCODE_TEXT_RESPONSE = 0x24
_IMMEDIATE_BIT = 0x40
_FINAL_BIT = 0x80

# Transit, CSG=LoginOperationalNegotiation(1), NSG=FullFeaturePhase(3).
_LOGIN_FLAGS = _FINAL_BIT | (1 << 2) | 3

_STATUS_SUCCESS = 0x00
# Status-Class values from RFC 7143 §11.13.5.
_STATUS_CLASS_NAMES = {
    0x00: "Success",
    0x01: "Redirection",
    0x02: "Initiator Error",
    0x03: "Target Error",
}
_STATUS_DETAIL_NAMES = {
    (0x02, 0x01): "Authentication failure",
    (0x02, 0x02): "Authorization failure (initiator IQN not permitted)",
    (0x02, 0x03): "Target not found",
    (0x02, 0x05): "Service unavailable",
    (0x02, 0x06): "Out of resources",
}

# A syntactically valid initiator name. Deliberately identifiable as a scanner so
# it is obvious in the target's log what connected.
INITIATOR_NAME = "iqn.2000-01.com.scanr:authorized-scan"

_TARGET_NAME_RE = re.compile(r"TargetName=([^\x00]+)")
_TARGET_ADDRESS_RE = re.compile(r"TargetAddress=([^\x00]+)")


@dataclass
class LoginResult:
    status_class: int
    status_detail: int
    data: bytes = b""

    @property
    def succeeded(self) -> bool:
        return self.status_class == _STATUS_SUCCESS

    def describe(self) -> str:
        name = _STATUS_CLASS_NAMES.get(self.status_class, f"0x{self.status_class:02x}")
        detail = _STATUS_DETAIL_NAMES.get((self.status_class, self.status_detail))
        rendered = f"Status-Class {self.status_class:#04x} ({name})"
        if detail:
            rendered += f", Status-Detail {self.status_detail:#04x} ({detail})"
        elif self.status_detail:
            rendered += f", Status-Detail {self.status_detail:#04x}"
        return rendered


@dataclass
class DiscoveredTargets:
    names: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def build_login_request(initiator_name: str = INITIATOR_NAME) -> bytes:
    """A discovery-session login request offering no authentication method.

    ``AuthMethod=None`` states plainly that we are not going to authenticate. A
    target configured for CHAP refuses it, which is the correct outcome and is
    reported as such.
    """
    text = (
        f"InitiatorName={initiator_name}\x00"
        "SessionType=Discovery\x00"
        "AuthMethod=None\x00"
        "HeaderDigest=None\x00"
        "DataDigest=None\x00"
    ).encode("ascii")
    payload = _pad4(text)

    header = bytearray(_BHS_LENGTH)
    header[0] = _IMMEDIATE_BIT | _OPCODE_LOGIN_REQUEST
    header[1] = _LOGIN_FLAGS
    header[2] = 0x00  # VersionMax
    header[3] = 0x00  # VersionMin
    header[4] = 0x00  # TotalAHSLength
    header[5:8] = len(text).to_bytes(3, "big")  # DataSegmentLength (unpadded)
    # ISID: T=00 (OUI format), A=0, B=0x0001, C=0, D=0x0001 — any unique value.
    header[8:14] = bytes([0x00, 0x00, 0x01, 0x00, 0x00, 0x01])
    header[14:16] = b"\x00\x00"  # TSIH = 0 for a new session
    header[16:20] = struct.pack(">I", 0x53434E31)  # InitiatorTaskTag
    header[20:22] = b"\x00\x00"  # CID
    header[24:28] = struct.pack(">I", 0)  # CmdSN
    header[28:32] = struct.pack(">I", 0)  # ExpStatSN
    return bytes(header) + payload


def build_sendtargets_request(command_sn: int = 1, stat_sn: int = 0) -> bytes:
    """A SendTargets=All text request — the discovery query itself."""
    text = b"SendTargets=All\x00"
    payload = _pad4(text)

    header = bytearray(_BHS_LENGTH)
    header[0] = _IMMEDIATE_BIT | _OPCODE_TEXT_REQUEST
    header[1] = _FINAL_BIT
    header[4] = 0x00
    header[5:8] = len(text).to_bytes(3, "big")
    header[16:20] = struct.pack(">I", 0x53434E32)  # InitiatorTaskTag
    header[20:24] = b"\xff\xff\xff\xff"  # TargetTransferTag = none
    header[24:28] = struct.pack(">I", command_sn)
    header[28:32] = struct.pack(">I", stat_sn)
    return bytes(header) + payload


def parse_login_response(raw: bytes) -> LoginResult | None:
    """Parse a Login Response PDU. None when the peer did not speak iSCSI."""
    if len(raw) < _BHS_LENGTH:
        return None
    if raw[0] & 0x3F != _OPCODE_LOGIN_RESPONSE:
        return None
    data_length = int.from_bytes(raw[5:8], "big")
    status_class = raw[36]
    status_detail = raw[37]
    data = raw[_BHS_LENGTH:_BHS_LENGTH + data_length]
    return LoginResult(status_class=status_class, status_detail=status_detail, data=data)


def parse_text_response(raw: bytes) -> DiscoveredTargets | None:
    """Extract TargetName/TargetAddress pairs from a Text Response PDU."""
    if len(raw) < _BHS_LENGTH:
        return None
    if raw[0] & 0x3F != _OPCODE_TEXT_RESPONSE:
        return None
    data_length = int.from_bytes(raw[5:8], "big")
    data = raw[_BHS_LENGTH:_BHS_LENGTH + data_length].decode("ascii", errors="replace")
    return DiscoveredTargets(
        names=_TARGET_NAME_RE.findall(data),
        addresses=_TARGET_ADDRESS_RE.findall(data),
    )


class IscsiExposurePlugin(PluginBase):
    id = "services.iscsi_exposure"
    name = "Unauthenticated iSCSI Target Exposure"
    description = (
        "Detect iSCSI portals that accept a discovery session without CHAP and "
        "enumerate the block targets they advertise"
    )
    category = PluginCategory.services
    severity = Severity.high
    ports = ISCSI_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        for port in host.ports:
            if port.number not in ISCSI_PORTS or port.state != "open":
                continue
            result = await self._discover(host.ip, port.number)
            if result is None:
                continue
            login, targets = result
            findings.append(self._build_finding(host.ip, port.number, login, targets))
        return findings

    async def _discover(
        self, ip: str, port: int
    ) -> tuple[LoginResult, DiscoveredTargets | None] | None:
        """Login, then SendTargets on the same connection. None if not iSCSI."""
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=_TIMEOUT
            )
            writer.write(build_login_request())
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT)
            raw = await asyncio.wait_for(reader.read(_READ_LIMIT), timeout=_TIMEOUT)
            login = parse_login_response(raw)
            if login is None:
                return None
            if not login.succeeded:
                return login, None

            writer.write(build_sendtargets_request())
            await asyncio.wait_for(writer.drain(), timeout=_TIMEOUT)
            raw = await asyncio.wait_for(reader.read(_READ_LIMIT), timeout=_TIMEOUT)
            return login, parse_text_response(raw)
        except (OSError, asyncio.TimeoutError, struct.error) as exc:
            logger.debug("iSCSI discovery failed %s:%d: %s", ip, port, exc)
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, asyncio.TimeoutError):
                    pass

    def _build_finding(
        self,
        ip: str,
        port: int,
        login: LoginResult,
        targets: DiscoveredTargets | None,
    ) -> FindingData:
        if not login.succeeded:
            return FindingData(
                plugin_id=self.id,
                severity=Severity.info,
                title="iSCSI Portal Requires Authentication",
                description=(
                    f"An iSCSI portal is listening on {ip}:{port} and refused a discovery "
                    "session that offered no authentication. That is the correct "
                    "behaviour, recorded here so the report shows the check ran and what "
                    "it concluded.\n\n"
                    "The portal is still a block-storage service reachable from this "
                    "network, which is worth confirming is intentional."
                ),
                evidence=(
                    f"Login Request (SessionType=Discovery, AuthMethod=None) to "
                    f"{ip}:{port}\nLogin Response: {login.describe()}"
                ),
                remediation=(
                    "No action required for the authentication itself. Confirm the portal "
                    "only needs to be reachable from the initiators that use it, and "
                    "restrict TCP/3260 to those hosts on a dedicated storage network."
                ),
                references=["https://datatracker.ietf.org/doc/html/rfc7143"],
                port_number=port,
                protocol="tcp",
            )

        names = targets.names if targets else []
        addresses = targets.addresses if targets else []
        # Named targets mean an attacker has everything needed to mount them.
        severity = Severity.critical if names else Severity.high

        evidence = [
            f"Login Request (SessionType=Discovery, AuthMethod=None, "
            f"InitiatorName={INITIATOR_NAME}) to {ip}:{port}",
            f"Login Response: {login.describe()} — the portal accepted a discovery "
            "session with no credential.",
        ]
        if names:
            evidence.append("")
            evidence.append(f"SendTargets=All returned {len(names)} target(s):")
            evidence.extend(f"  {name}" for name in names[:25])
            if len(names) > 25:
                evidence.append(f"  [... {len(names) - 25} more]")
        if addresses:
            evidence.append("Target portal addresses:")
            evidence.extend(f"  {address}" for address in addresses[:25])
        if not names:
            evidence.append(
                "\nSendTargets returned no target names. The discovery session itself "
                "was still established without authentication."
            )
        evidence.append(
            "\nNo target login was attempted, so no volume was attached and no block "
            "was read or written."
        )

        target_sentence = (
            f"The portal then listed {len(names)} target(s) in response to SendTargets, "
            "so an attacker does not even need to guess an IQN."
            if names
            else "SendTargets returned no names, but the unauthenticated discovery "
            "session was established."
        )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title=(
                f"Unauthenticated iSCSI Discovery — {len(names)} Target(s) Exposed"
                if names
                else "Unauthenticated iSCSI Discovery Session Accepted"
            ),
            description=(
                f"The iSCSI portal on {ip}:{port} accepted a discovery session that "
                f"explicitly offered no authentication method. {target_sentence}\n\n"
                "iSCSI exports block devices, not files. An initiator that can log into a "
                "target attaches the disk as local storage, which puts it entirely outside "
                "the filesystem's own permission model: the volume can be mounted "
                "elsewhere and read and written in full, regardless of the ACLs the owning "
                "operating system applies.\n\n"
                "What sits on iSCSI is usually the highest-value data on the network — VM "
                "datastores, database volumes, backup repositories. Block access to a "
                "hypervisor datastore is access to every virtual machine's disk, including "
                "domain controllers. Block access to a backup volume means both reading the "
                "backups and destroying them, which is the step that turns a ransomware "
                "incident into an unrecoverable one.\n\n"
                "Note that initiator-IQN allowlisting is not a defence here: the IQN is a "
                "string the client supplies, and this check supplied its own."
            ),
            evidence="\n".join(evidence),
            remediation=(
                "Require mutual CHAP on both the discovery session and each target, not "
                "one-way CHAP and not IQN allowlisting alone. Configure it on the target: "
                "Linux LIO/targetcli — set 'authentication=1' and per-ACL userid/password "
                "on the TPG; Windows iSCSI Target — enable CHAP per target and reverse CHAP "
                "for mutual authentication; Synology/QNAP/TrueNAS — enable CHAP in the "
                "target's settings, which is off by default.\n\n"
                "Then treat the network as the primary control. iSCSI is a storage-fabric "
                "protocol and should be on a dedicated, non-routed storage VLAN reachable "
                "only by the hosts that mount the volumes — never from a user network and "
                "never from the internet. Restrict TCP/3260 accordingly.\n\n"
                "Where the data warrants it, enable IPsec for the iSCSI session: CHAP "
                "authenticates the login but does not encrypt the traffic, so block data "
                "and anything in it crosses the network in cleartext.\n\n"
                "If this portal was reachable from an untrusted network, treat the volumes "
                "as potentially copied: review target-side connection logs for initiator "
                "IQNs that do not match known hosts, and rotate any credential stored on "
                "those volumes."
            ),
            references=[
                "https://datatracker.ietf.org/doc/html/rfc7143",
                "https://attack.mitre.org/techniques/T1200/",
                "https://www.cisa.gov/news-events/alerts",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=f"iscsiadm -m discovery -t sendtargets -p {ip}:{port}",
        )
