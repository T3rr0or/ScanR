"""Internal domain and host disclosure through HTTP NTLM authentication.

An IIS endpoint configured for Windows authentication answers an NTLM
``Type 1`` negotiate message with a ``Type 2`` challenge. That challenge is sent
*before* any credential is supplied, and it is not empty: it carries the server's
NetBIOS computer name, its NetBIOS domain name, its DNS host and domain names,
the AD forest root, and — when the server advertises its version — the exact
Windows build number.

So an unauthenticated request returns the internal AD namespace of a host that is
otherwise only reachable by name. That is the information an attacker needs
before anything else: the domain to target for Kerberos attacks, the internal DNS
suffix to fold into subdomain discovery, the machine's real hostname behind a
load balancer or reverse proxy, and a precise OS build to match against patch
level.

No credentials are sent and no authentication is attempted — a Type 1 message
carries no username, no password and no hash. The server volunteers all of this
in its first reply.
"""
from __future__ import annotations

import base64
import binascii
import logging
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanr.core.plugin_base import FindingData, PluginBase, PluginCategory, Severity
from scanr.plugins.web._crawler import create_web_client
from scanr.plugins.web._ports import is_web_port, web_scheme

if TYPE_CHECKING:
    from scanr.core.context import ScanContext
    from scanr.models import Host

logger = logging.getLogger(__name__)

HTTP_PORTS = [80, 443, 8080, 8443, 8000, 5985, 5986]

_SIGNATURE = b"NTLMSSP\x00"
_TYPE_NEGOTIATE = 1
_TYPE_CHALLENGE = 2

# Flags a real client sends: request the target name and its AV-pair details, and
# ask the server to declare its version. TARGET_INFO and VERSION are what make
# the reply informative.
_NEGOTIATE_FLAGS = (
    0x00000001  # UNICODE
    | 0x00000002  # OEM
    | 0x00000004  # REQUEST_TARGET
    | 0x00000200  # NTLM
    | 0x00008000  # ALWAYS_SIGN
    | 0x00080000  # EXTENDED_SESSIONSECURITY
    | 0x00800000  # TARGET_INFO
    | 0x02000000  # VERSION
)
_FLAG_NEGOTIATE_VERSION = 0x02000000

# Endpoints that commonly have Windows authentication enabled. Each is a plain
# GET; the NTLM handshake is what is being measured, not the content.
_NTLM_PATHS = (
    "/ews/",
    "/rpc/",
    "/autodiscover/autodiscover.xml",
    "/mapi/emsmdb/",
    "/oab/",
    "/powershell/",
    "/Microsoft-Server-ActiveSync",
    "/owa/",
    "/aspnet_client/",
    "/RDWeb/",
    "/remote/",
    "/wsman",
    "/api/",
    "/",
)

# MsvAvId values from MS-NLMP 2.2.2.1, named as they appear in a report.
_AV_PAIR_LABELS = {
    1: "NetBIOS computer name",
    2: "NetBIOS domain name",
    3: "DNS computer name",
    4: "DNS domain name",
    5: "DNS forest (tree) name",
}
_AV_PAIR_EOL = 0

_WINDOWS_BUILDS = {
    (10, 0): "Windows 10 / Server 2016-2025 (build identifies the release)",
    (6, 3): "Windows 8.1 / Server 2012 R2",
    (6, 2): "Windows 8 / Server 2012",
    (6, 1): "Windows 7 / Server 2008 R2",
    (6, 0): "Windows Vista / Server 2008",
    (5, 2): "Windows Server 2003",
    (5, 1): "Windows XP",
}
# Builds at or below this are past end of support for every edition.
_END_OF_SUPPORT_MAJOR = 6


@dataclass
class NtlmChallenge:
    """What a Type 2 challenge disclosed."""

    target_name: str = ""
    av_pairs: dict[int, str] = field(default_factory=dict)
    os_version: str = ""
    os_build: tuple[int, int, int] | None = None

    @property
    def netbios_domain(self) -> str:
        return self.av_pairs.get(2, "")

    @property
    def netbios_computer(self) -> str:
        return self.av_pairs.get(1, "")

    @property
    def dns_domain(self) -> str:
        return self.av_pairs.get(4, "")

    @property
    def dns_computer(self) -> str:
        return self.av_pairs.get(3, "")

    @property
    def forest(self) -> str:
        return self.av_pairs.get(5, "")

    def disclosed(self) -> dict[str, str]:
        """Named values worth reporting, in the order a reader wants them."""
        values = {
            "NetBIOS domain": self.netbios_domain,
            "NetBIOS computer": self.netbios_computer,
            "DNS domain": self.dns_domain,
            "DNS computer": self.dns_computer,
            "AD forest": self.forest,
            "Target name": self.target_name,
            "Windows version": self.os_version,
        }
        return {key: value for key, value in values.items() if value}


def build_type1_message() -> str:
    """A base64 NTLM Type 1 (negotiate) message carrying no credential at all."""
    message = _SIGNATURE
    message += struct.pack("<I", _TYPE_NEGOTIATE)
    message += struct.pack("<I", _NEGOTIATE_FLAGS)
    # Empty domain and workstation fields: length, max length, offset.
    message += struct.pack("<HHI", 0, 0, 32)
    message += struct.pack("<HHI", 0, 0, 32)
    return base64.b64encode(message).decode("ascii")


def _read_utf16(raw: bytes) -> str:
    try:
        return raw.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace").rstrip("\x00")


def parse_av_pairs(raw: bytes) -> dict[int, str]:
    """Decode the TargetInfo AV-pair list (MS-NLMP 2.2.2.1)."""
    pairs: dict[int, str] = {}
    position = 0
    while position + 4 <= len(raw):
        av_id, av_len = struct.unpack("<HH", raw[position:position + 4])
        position += 4
        if av_id == _AV_PAIR_EOL:
            break
        if position + av_len > len(raw):
            break
        if av_id in _AV_PAIR_LABELS:
            pairs[av_id] = _read_utf16(raw[position:position + av_len])
        position += av_len
    return pairs


def describe_build(major: int, minor: int, build: int) -> str:
    base = _WINDOWS_BUILDS.get((major, minor), f"Windows {major}.{minor}")
    return f"{base} — version {major}.{minor} build {build}"


def parse_challenge(header_value: str) -> NtlmChallenge | None:
    """Parse the base64 Type 2 message out of a WWW-Authenticate header.

    Returns None for anything that is not a well-formed NTLM challenge, so a
    server that answers with a different scheme, or with truncated data, is not
    reported as having disclosed anything.
    """
    token = header_value.strip()
    for prefix in ("NTLM ", "Negotiate "):
        if token.upper().startswith(prefix.upper()):
            token = token[len(prefix):].strip()
            break
    else:
        return None
    if not token:
        return None
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None

    # signature(8) + type(4) + target name fields(8) + flags(4) + challenge(8)
    if len(raw) < 32 or raw[:8] != _SIGNATURE:
        return None
    (message_type,) = struct.unpack("<I", raw[8:12])
    if message_type != _TYPE_CHALLENGE:
        return None

    challenge = NtlmChallenge()

    name_len, _name_max, name_offset = struct.unpack("<HHI", raw[12:20])
    if name_len and name_offset + name_len <= len(raw):
        challenge.target_name = _read_utf16(raw[name_offset:name_offset + name_len])

    (flags,) = struct.unpack("<I", raw[20:24])

    if len(raw) >= 48:
        info_len, _info_max, info_offset = struct.unpack("<HHI", raw[40:48])
        if info_len and info_offset + info_len <= len(raw):
            challenge.av_pairs = parse_av_pairs(raw[info_offset:info_offset + info_len])

    if flags & _FLAG_NEGOTIATE_VERSION and len(raw) >= 56:
        major, minor, build = struct.unpack("<BBH", raw[48:52])
        if major:
            challenge.os_build = (major, minor, build)
            challenge.os_version = describe_build(major, minor, build)

    return challenge if challenge.disclosed() else None


class NtlmEndpointDisclosurePlugin(PluginBase):
    id = "web.ntlm_endpoint_disclosure"
    name = "NTLM Endpoint Information Disclosure"
    description = (
        "Recover the internal AD domain, computer name, DNS suffix and Windows "
        "build from an HTTP NTLM challenge, without sending any credential"
    )
    category = PluginCategory.web
    severity = Severity.medium
    ports = HTTP_PORTS

    async def check(self, context: "ScanContext", host: "Host") -> list[FindingData]:
        findings: list[FindingData] = []
        authority = getattr(host, "hostname", None) or host.ip
        for port in host.ports:
            if not is_web_port(port):
                continue
            base_url = f"{web_scheme(port)}://{authority}:{port.number}"
            try:
                result = await self._probe_port(context, base_url, host.ip, port.number, authority)
            except Exception as exc:  # noqa: BLE001 - one port must not end the scan
                logger.debug("ntlm_endpoint_disclosure: %s failed: %s", base_url, exc)
                continue
            if result is not None:
                path, challenge = result
                findings.append(self._build_finding(base_url, path, challenge, port.number))
        return findings

    async def _probe_port(
        self, context, base_url: str, pin_ip: str, pin_port: int, authority: str
    ) -> tuple[str, NtlmChallenge] | None:
        type1 = build_type1_message()
        async with create_web_client(
            context, pin_ip=pin_ip, pin_port=pin_port, pin_hostname=authority
        ) as client:
            for path in _NTLM_PATHS:
                challenge = await self._negotiate(client, f"{base_url}{path}", type1)
                if challenge is not None:
                    return path, challenge
        return None

    @staticmethod
    async def _negotiate(client, url: str, type1: str) -> NtlmChallenge | None:
        try:
            response = await client.get(
                url, headers={"Authorization": f"NTLM {type1}"}, timeout=8.0
            )
        except Exception:
            return None
        if response.status_code != 401:
            return None
        # A server may offer several schemes; only the NTLM/Negotiate one carries
        # a challenge, and httpx joins repeated headers with ", ".
        header = response.headers.get("www-authenticate", "")
        for candidate in header.split(","):
            challenge = parse_challenge(candidate)
            if challenge is not None:
                return challenge
        return parse_challenge(header)

    def _build_finding(
        self, base_url: str, path: str, challenge: NtlmChallenge, port: int
    ) -> FindingData:
        disclosed = challenge.disclosed()
        # A bare target name is far less useful than the full AD namespace, so it
        # is not rated the same.
        severity = (
            Severity.medium
            if challenge.netbios_domain or challenge.dns_domain
            else Severity.low
        )

        evidence = [
            f"GET {base_url}{path} with 'Authorization: NTLM <Type 1>' → 401",
            "Server replied with an NTLM Type 2 challenge. Decoded fields:",
        ]
        evidence.extend(f"  {label}: {value}" for label, value in disclosed.items())
        evidence.append("")
        evidence.append(
            "The Type 1 message contained no username, password or hash — every value "
            "above was volunteered before authentication."
        )

        eol_note = ""
        if challenge.os_build and challenge.os_build[0] <= _END_OF_SUPPORT_MAJOR:
            eol_note = (
                f"\n\nThe reported version ({challenge.os_version}) is past end of "
                "support, so this host is not receiving security updates. Confirm it "
                "against the asset inventory — a disclosed build this old is usually "
                "either a forgotten server or an appliance nobody owns."
            )

        return FindingData(
            plugin_id=self.id,
            severity=severity,
            title="Internal Domain and Host Names Disclosed via HTTP NTLM",
            description=(
                f"The endpoint {base_url}{path} performs NTLM authentication and returns "
                "a challenge to any unauthenticated request. That challenge discloses the "
                "server's internal Active Directory names and, where advertised, its exact "
                "Windows build.\n\n"
                "This is reconnaissance an attacker cannot otherwise get from outside: the "
                "NetBIOS and DNS domain names identify which AD domain to target for "
                "Kerberos attacks such as AS-REP roasting and password spraying; the "
                "internal DNS suffix expands subdomain enumeration onto names that are not "
                "in public DNS; the computer name identifies the real host behind a load "
                "balancer or reverse proxy; and the build number pins the patch level "
                "precisely enough to pick an exploit before sending a single payload."
                + eol_note
            ),
            evidence="\n".join(evidence),
            remediation=(
                "Decide whether this endpoint should face untrusted networks at all. NTLM "
                "cannot be made to withhold these fields — disclosing them is how the "
                "protocol works — so the fix is to change what is exposed, not to "
                "reconfigure NTLM.\n\n"
                "Put the endpoint behind an authenticating reverse proxy or VPN so the "
                "challenge is only issued to clients that have already been "
                "authenticated. Where the service must stay public (Exchange, RD Web, "
                "ActiveSync), move it to modern authentication / OAuth and disable NTLM "
                "and Negotiate on the virtual directory; for Exchange, publish it through "
                "a pre-authenticating gateway. Restrict paths that do not need to be "
                "public at all — /rpc/, /powershell/ and /aspnet_client/ rarely do.\n\n"
                "Accept the residual disclosure where the endpoint must remain reachable, "
                "and account for it: the domain name is public, so password spraying and "
                "roasting are reachable pre-conditions. Enforce account lockout, "
                "Kerberos AES-only where possible, and alerting on spray patterns."
            ),
            references=[
                "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/",
                "https://www.gosecure.net/blog/2020/10/27/microsoft-windows-ntlm-information-disclosure/",
            ],
            port_number=port,
            protocol="tcp",
            peer_review_command=(
                f"curl -sI -H 'Authorization: NTLM {build_type1_message()}' "
                f"{base_url}{path} | grep -i www-authenticate"
            ),
        )
